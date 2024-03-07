from dataclasses import dataclass
from typing import Optional, Self, Tuple
from messages import (
    FileSendMessage,
    Message,
    MessageCode,
    PublicKeyMessage,
    ReconnectMessage,
    RegisterMessage,
)
from abc import ABC, abstractmethod
import uuid
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
import hashlib

VERSION = 3


class FileRepo:
    def __init__(self) -> None:
        self.pub_keys: dict[str, bytes] = dict()

    """managing the storage of files"""

    def save_file(self, files_name: str, content: bytes, packet=-1, packet_count=-1):
        # TODO make sure files not being overrun, especially not important ones
        with open(files_name, "wb") as f:
            f.write(content)

    def save_pub_key(self, key: bytes, user: str):
        # protect from overriding
        self.pub_keys[user] = key

    def get_pub_key(self, user: str) -> Tuple[bytes, bool]:
        if user not in self.pub_keys:
            return bytes(), False
        return self.pub_keys[user], True


class Session(ABC):
    @abstractmethod
    def proccess_message(self, message: Message) -> Tuple[Self, Response]:
        pass


@dataclass
class EncryptedSession(Session):
    """encrytion established, waiting for file"""

    private_key: bytes
    client_id: bytes
    _file_repo: FileRepo

    def proccess_message(self, message: Message) -> Tuple[Session, Response]:
        if isinstance(message.content, FileSendMessage):
            cipher = AES.new(self.private_key, AES.MODE_CBC)
            plaintext = cipher.decrypt(message.content.encrypted_content)

            file_hash = hashlib.md5()
            file_hash.update(plaintext)
            cksum = file_hash.digest()

            self._file_repo.save_file(
                message.content.name, plaintext
            )  # TODO handle multipacketfiles
            rc = FileAcceptedWithCRC(
                self.client_id,
                message.content.content_size,
                message.content.file_name,
                cksum,
            )
            return RegisteredUserSession(self.client_id, self._file_repo), Response(
                ResponseHeader(VERSION, rc.code, rc.size()), rc
            )
        else:
            raise Exception("Unexpected message type")


@dataclass
class RegisteredUserSession(Session):
    """after getting / retriving RSA public key, ready to send sessions AES"""

    client_id: bytes
    _file_repo: FileRepo

    def proccess_message(self, message: Message) -> Tuple[Session, Response]:
        if isinstance(message.content, PublicKeyMessage):
            public_key = message.content.public_key
            self._file_repo.save_pub_key(
                message.content.public_key, message.content.name
            )

        elif isinstance(message.content, ReconnectMessage):
            public_key, success = self._file_repo.get_pub_key(message.content.name)
            if not success:
                content = DeclineReconnect(self.client_id)
                return NewSession(self._file_repo), Response(
                    ResponseHeader(VERSION, content.code, content.size()), content
                )

        else:
            raise Exception("Unexpected message type")

        random = Random.new()
        aes_key = random.read(256)
        rsa_public_key = RSA.importKey(public_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes = rsa_public_key.encrypt(aes_key)

        if isinstance(message.content, PublicKeyMessage):
            content = EncryptedAESKey(self.client_id, encrypted_aes)

        else:
            content = ApproveReconnect(self.client_id, encrypted_aes)

        return EncryptedSession(aes_key, self.client_id, self._file_repo), Response(
            ResponseHeader(VERSION, content.code, content.size()), content
        )


class NewSession(Session):
    """before getting any messages"""

    _file_repo: FileRepo
    _is_used: bool

    def __init__(self, fr: FileRepo) -> None:
        self._file_repo = fr
        self._is_used = False

    def proccess_message(
        self, message: Message
    ) -> Tuple[RegisteredUserSession, Response]:
        assert not self._is_used, "Session cant be used twice"
        self._is_used = True

        if not isinstance(message.content, RegisterMessage):
            raise Exception("Unidetified message type")

        new_id = uuid.uuid4().bytes[:16]
        c = SuccessfulRegistration(new_id)
        return RegisteredUserSession(new_id, self._file_repo), Response(
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

    def __init__(self, fr: FileRepo) -> None:
        self.sessions = dict()
        self._file_repo = fr

    def proccess_message(self, message: Message) -> Optional[Response]:
        if message.header.code == MessageCode.register:
            next_session, resp = NewSession(
                self._file_repo,
            ).proccess_message(message)
            key = resp.content.new_id  # type: ignore

        elif message.header.code in [MessageCode.crc_good, MessageCode.crc_give_up]:
            content = AckMessage(message.header.client_id)
            return Response(
                ResponseHeader(VERSION, content.code, content.size()), content
            )

        elif message.header.code == MessageCode.crc_bad:
            return

        else:
            key = message.header.client_id
            if key not in self.sessions.keys():
                rc = FaileRegistration()
                return Response(
                    ResponseHeader(VERSION, rc.code, rc.size()),
                    rc,
                )

            curr_session = self.sessions[key]
            next_session, resp = curr_session.proccess_message(message)

        self.sessions[key] = next_session
        return resp
