import typing
from dataclasses import dataclass

VERSION_LENGTH = 1
CODE_LENGTH = 2
PAYLOAD_SIZE_LENGTH = 4
TOTAL_HEADER_LENGTH = VERSION_LENGTH + CODE_LENGTH + PAYLOAD_SIZE_LENGTH


@dataclass
class ResponseHeader:
    version: int
    code: int
    payload_size: int

    def encode(self) -> bytes:
        return (
            self.version.to_bytes(1)
            + self.code.to_bytes(2)
            + self.payload_size.to_bytes(4)
        )


@dataclass
class FileAcceptedWithCRC:
    client_id: bytes
    content_size: int
    file_name: str
    cksum: bytes
    code = 1603

    def encode(self) -> bytes:
        return (
            self.client_id
            + self.content_size.to_bytes(4)
            + self.file_name.encode("utf-8")
            + self.cksum
        )

    def size(self) -> int:
        return 279


@dataclass
class EncryptedAESKey:
    client_id: bytes
    encrypted_aes: bytes
    code = 1602

    def encode(self) -> bytes:
        return self.client_id + self.encrypted_aes

    def size(self) -> int:
        return 16 + len(self.encrypted_aes)


@dataclass
class SuccessfulRegistration:
    new_id: bytes
    code = 1600

    def encode(self) -> bytes:
        return self.new_id

    def size(self) -> int:
        return 16


class FaileRegistration:
    code = 1601

    def encode(self) -> bytes:
        return bytes()

    def size(self) -> int:
        return 0


@dataclass
class AckMessage:
    client_id: bytes
    code = 1604

    def encode(self) -> bytes:
        return self.client_id

    def size(self):
        return 16


@dataclass
class ApproveReconnect:
    client_id: bytes
    code = 1605
    encrypted_aes: bytes

    def encode(self) -> bytes:
        return self.client_id + self.encrypted_aes

    def size(self) -> int:
        return 16 + len(self.encrypted_aes)


@dataclass
class DeclineReconnect:
    client_id: bytes
    code = 1606

    def encode(self) -> bytes:
        return self.client_id

    def size(self):
        return 16


ResponseContent = typing.Union[
    SuccessfulRegistration,
    FaileRegistration,
    EncryptedAESKey,
    FileAcceptedWithCRC,
    AckMessage,
    ApproveReconnect,
    DeclineReconnect,
]


@dataclass
class Response:
    header: ResponseHeader
    content: ResponseContent

    def encode(self) -> bytes:
        return self.header.encode() + self.content.encode()
