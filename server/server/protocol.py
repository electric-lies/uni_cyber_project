import sqlite3
from dataclasses import dataclass
import logging
from typing import Optional, Self, Tuple
from messages import (
    CrcBadMessage,
    CrcGoodMessage,
    FileSendMessage,
    Message,
    MessageCode,
    PublicKeyMessage,
    ReconnectMessage,
    RegisterMessage,
)
from abc import ABC, abstractmethod
import uuid
import time
from responses import (
    AckMessage,
    ApproveReconnect,
    DeclineReconnect,
    EncryptedAESKey,
    FaileRegistration,
    FileAcceptedWithCRC,
    Response,
    ResponseHeader,
    SuccessfulRegistration,
)
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from crcfile import crctab
from pathlib import Path
VERSION = 3


class FileRepo:
    def __init__(self, con: sqlite3.Connection) -> None:
        self.pub_keys: dict[str, bytes] = dict()
        self._con = con

    """managing the storage of files"""

    def ack(self, cid: bytes, file: str):
        cur = self._con.cursor()
        cur.execute(
            """
                UPDATE files SET Verified = 1 Where ID = ? and FileName = ?
            """,
            (cid.hex(), file),
        )
        cur.close()
        self._con.commit()

    def save_file(
        self, cid: bytes, file_name: str, content: bytes, packet=-1, packet_count=-1
    ):
        # TODO make sure files not being overrun, especially not important ones
        logging.info(
            f"writing {len(content)} bytes to file {file_name}, {packet}/{packet_count}"
        )

        path = Path(f"./files/{cid.hex()}")
        path.mkdir()
        with open(path / file_name.rstrip("\x00"), "w") as f:
            f.write(content.decode("utf-8"))
        cur = self._con.cursor()
        cur.execute(
            """
                INSERT INTO files VALUES (?,?,?,?) 
            """,
            (cid.hex(), file_name, cid.hex() + "/" + file_name, 0),
        )
        cur.close()
        self._con.commit()

class Session(ABC):
    @abstractmethod
    def proccess_message(self, message: Message) -> Tuple[Self, Response]:
        pass


UNSIGNED = lambda n: n & 0xFFFFFFFF


def memcrc(b: bytes) -> bytes:
    print(f"memcrc {b=}")
    n = len(b)
    c = s = 0
    for ch in b:
        tabidx = (s >> 24) ^ ch
        s = UNSIGNED((s << 8)) ^ crctab[tabidx]

    while n:
        c = n & 0o377
        n = n >> 8
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
    res = UNSIGNED(~s)
    logging.info(f"memcrc {res=}")
    return res.to_bytes(4, "little")


@dataclass
class EncryptedSession(Session):
    """encrytion established, waiting for file"""

    private_key: bytes
    client_id: bytes
    _file_repo: FileRepo
    _con: sqlite3.Connection

    def proccess_message(self, message: Message) -> Tuple[Session, Response]:
        if isinstance(message.content, CrcGoodMessage) or isinstance(
            message.content, CrcBadMessage
        ):
            rc = AckMessage(self.client_id)
            self._file_repo.ack(message.header.client_id, message.content.file_name)
            return RegisteredUserSession(
                self.client_id, self._file_repo, self._con
            ), Response(ResponseHeader(VERSION, rc.code, rc.size()), rc)

        if isinstance(message.content, FileSendMessage):
            cipher = AES.new(
                self.private_key, AES.MODE_CBC, iv=int(0).to_bytes(16, "little")
            )
            ctext = message.content.encrypted_content
            plaintext = cipher.decrypt(ctext)
            logging.info(
                f"the {len(message.content.encrypted_content)} bytes long ciphertext named {message.content.file_name} was decrypted to the following text: {plaintext}"
            )

            cksum = memcrc(plaintext)

            self._file_repo.save_file(
                message.header.client_id, message.content.file_name, plaintext
            )  # TODO handle multipacketfiles
            rc = FileAcceptedWithCRC(
                self.client_id,
                message.content.content_size,
                message.content.file_name,
                cksum,
            )
            return self, Response(ResponseHeader(VERSION, rc.code, rc.size()), rc)

        else:
            raise Exception("Unexpected message type")


@dataclass
class RegisteredUserSession(Session):
    """after getting / retriving RSA public key, ready to send sessions AES"""

    client_id: bytes
    _file_repo: FileRepo
    _con: sqlite3.Connection

    def _save_pub_key(self, key: bytes, cid: bytes):
        cur = self._con.cursor()
        cur.execute(
            f"""
                                   UPDATE clients
                                   SET PublicKey = ?
                                   WHERE ID = ?
                                   """,
            (key, cid.hex()),
        )
        cur.close()
        self._con.commit()

    def _get_pub_key(self, cid: bytes) -> Tuple[bytes, bool]:
        cur = self._con.cursor()
        res = cur.execute(
            """
                                         select PublicKey
                                         from clients
                                         where ID = ?
                                         """,
            (cid.hex(),),
        ).fetchone()
        cur.close()
        if res is not None:
            return res[0], True
        else:
            return b"", False

    def _save_private_key(self, key: bytes, cid: bytes):
        cur = self._con.cursor()
        cur.execute(
            f"""
                                   UPDATE clients
                                   SET AES = ?
                                   WHERE ID = ?
                                   """,
            (key, cid.hex()),
        )
        cur.close()
        self._con.commit()

    def proccess_message(self, message: Message) -> Tuple[Session, Response]:
        if isinstance(message.content, PublicKeyMessage):
            public_key = message.content.public_key
            self._save_pub_key(message.content.public_key, message.header.client_id)

        elif isinstance(message.content, ReconnectMessage):
            public_key, success = self._get_pub_key(message.header.client_id)
            if not success:
                content = DeclineReconnect(self.client_id)
                return NewSession(self._file_repo, self._con), Response(
                    ResponseHeader(VERSION, content.code, content.size()), content
                )

        else:
            raise Exception("Unexpected message type")

        random = Random.new()
        aes_key = random.read(16)
        self._save_private_key(aes_key, self.client_id)
        logging.info(f"AES key is {aes_key.hex()}, RSA key is {public_key}")
        rsa_public_key = RSA.importKey(public_key)
        logging.info(f"{len(aes_key)=}, {len(public_key)=}")
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes = rsa_public_key.encrypt(aes_key)

        if isinstance(message.content, PublicKeyMessage):
            content = EncryptedAESKey(self.client_id, encrypted_aes)

        else:
            content = ApproveReconnect(self.client_id, encrypted_aes)

        return EncryptedSession(
            aes_key, self.client_id, self._file_repo, self._con
        ), Response(ResponseHeader(VERSION, content.code, content.size()), content)


class NewSession(Session):
    """before getting any messages"""

    _file_repo: FileRepo
    _is_used: bool
    _con: sqlite3.Connection

    def __init__(self, fr: FileRepo, con: sqlite3.Connection) -> None:
        self._file_repo = fr
        self._is_used = False
        self._con = con

    def proccess_message(
        self, message: Message
    ) -> Tuple[RegisteredUserSession, Response]:
        assert not self._is_used, "Session cant be used twice"
        self._is_used = True

        if not isinstance(message.content, RegisterMessage):
            raise Exception("Unidetified message type")

        new_id = uuid.uuid4().bytes
        c = SuccessfulRegistration(new_id)

        cur = self._con.cursor()
        try:
            self._con.set_trace_callback(print)
            cur.execute(
                """
                        INSERT INTO clients VALUES
                        (?, ?, zeroblob(160), ?,zeroblob(32))
                       """,
                (new_id.hex(), message.content.name.rstrip("\x00"), int(time.time())),
            )
            cur.close()
            self._con.commit()

        except sqlite3.Error as er:
            logging.error(
                (new_id.hex(), message.content.name.rstrip("\x00"), int(time.time()))
            )
            logging.error(er)
            logging.error(er.sqlite_errorcode)  # Prints 275
            logging.error(er.sqlite_errorname)  # Prints SQLITE_CONSTRAINT_CHECK

        return RegisteredUserSession(new_id, self._file_repo, self._con), Response(
            ResponseHeader(
                VERSION,
                c.code,
                c.size(),
            ),
            c,
        )
        # elif isinstance(message.content, RegisterMessage):
        #    pass


class SessionStore:
    """stores sessions and create new ones when needed"""

    sessions: dict[bytes, Session]
    _file_repo: FileRepo

    def __init__(self, db_name: str) -> None:
        self.sessions = dict()
        self._con = sqlite3.connect(db_name)
        self._file_repo = FileRepo(self._con)

    def _get_reconnect_session_from_db(self, key: bytes) -> Optional[Session]:
        cur = self._con.cursor()
        res = cur.execute(
            f"""
                    select Name
                    from clients
                    where ID = ?
                    """,
            (key.hex(),),
        )
        client = res.fetchone()
        cur.close()
        if client is None:
            return None
        else:
            return RegisteredUserSession(key, self._file_repo, self._con)

    def proccess_message(self, message: Message) -> Optional[Response]:
        if message.header.code == MessageCode.register:
            next_session, resp = NewSession(
                self._file_repo, self._con
            ).proccess_message(message)
            key = resp.content.new_id  # type: ignore

        else:
            key = message.header.client_id
            if key not in self.sessions.keys():
                session = self._get_reconnect_session_from_db(key)
                if session is None:
                    rc = FaileRegistration()
                    return Response(
                        ResponseHeader(VERSION, rc.code, rc.size()),
                        rc,
                    )
                else:
                    self.sessions[key] = session

            curr_session = self.sessions[key]
            next_session, resp = curr_session.proccess_message(message)

        self.sessions[key] = next_session
        return resp
