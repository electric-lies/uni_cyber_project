from dataclasses import dataclass
from enum import Enum
import typing

CLIENT_ID_LENGTH = 16
VERSION_LENGTH = 1
CODE_LENGTH = 2
PAYLOAD_SIZE_LENGTH = 4
TOTAL_HEADER_LENGTH = (
    CLIENT_ID_LENGTH + VERSION_LENGTH + CODE_LENGTH + PAYLOAD_SIZE_LENGTH
)

USER_NAME_LENGTH = 255
PUBLICK_KEY_LENGTH = 160


class MessageCode(Enum):
    register = 1025
    public_key = 1026
    reconnect = 1027
    file = 1028
    crc_good = 1029
    crc_bad = 1030
    crc_give_up = 1031
    # TODO: more codes

    def minimal_required_content(self):
        match self.value:
            case MessageCode.register:
                return USER_NAME_LENGTH
            case MessageCode.public_key:
                return USER_NAME_LENGTH + PUBLICK_KEY_LENGTH
        return 0
        # TODO: more codes


@dataclass
class MessageHeader:
    client_id: bytes
    version: int
    code: MessageCode
    payload_size: int


def parse_message_header(bytes_header: bytes) -> MessageHeader:
    client_id = bytes_header[:CLIENT_ID_LENGTH]
    bytes_header = bytes_header[CLIENT_ID_LENGTH:]

    version = bytes_header[:VERSION_LENGTH]
    bytes_header = bytes_header[VERSION_LENGTH:]

    code = bytes_header[:CODE_LENGTH]
    bytes_header = bytes_header[CODE_LENGTH:]

    payload_size = bytes_header[:PAYLOAD_SIZE_LENGTH]
    # bytes_header = bytes_header[PAYLOAD_SIZE_LENGTH:]

    return MessageHeader(
        client_id,
        int.from_bytes(version),
        MessageCode(int.from_bytes(code)),
        int.from_bytes(payload_size),
    )


@dataclass
class FileSendMessage:
    content_size: int
    orig_file_size: int
    current_packet: int
    total_packets: int
    file_name: str
    encrypted_content: bytes

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(
            int.from_bytes(content[:4]),
            int.from_bytes(content[4:8]),
            int.from_bytes(content[8:10]),
            int.from_bytes(content[10:12]),
            content[12:267].decode(),
            content[267:],
        )


@dataclass
class CrcGoodMessage:
    file_name: str

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(content[:USER_NAME_LENGTH].decode())


@dataclass
class CrcBadMessage:
    file_name: str

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(content[:USER_NAME_LENGTH].decode())


@dataclass
class CrcEnoughMessage:
    file_name: str

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(content[:USER_NAME_LENGTH].decode())


@dataclass
class ReconnectMessage:
    name: str

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(content[:USER_NAME_LENGTH].decode())


@dataclass
class RegisterMessage:
    name: str

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(content[:USER_NAME_LENGTH].decode())


@dataclass
class PublicKeyMessage:
    name: str
    public_key: bytes

    @classmethod
    def from_bytes(cls, content: bytes):
        return cls(
            content[:USER_NAME_LENGTH].decode(),
            content[USER_NAME_LENGTH : USER_NAME_LENGTH + PUBLICK_KEY_LENGTH],
        )


MessageContent = typing.Union[RegisterMessage, PublicKeyMessage]

MESSAGE_CODE_TO_CLASS: dict[MessageCode, type] = {
    MessageCode.register: RegisterMessage,
    MessageCode.public_key: PublicKeyMessage,
    MessageCode.reconnect: ReconnectMessage,
    MessageCode.file: FileSendMessage,
    MessageCode.crc_good: CrcGoodMessage,
    MessageCode.crc_bad: CrcBadMessage,
    MessageCode.crc_give_up: CrcEnoughMessage,
}


def parse_meesage_content(code: MessageCode, bytes_content: bytes) -> MessageContent:
    return MESSAGE_CODE_TO_CLASS[code].from_bytes(bytes_content)  # type: ignore


@dataclass
class Message:
    header: MessageHeader
    content: MessageContent


def parse_message(bytes_message: bytes) -> Message:
    assert len(bytes_message) > TOTAL_HEADER_LENGTH, "Message too short"
    bytes_header = bytes_message[:TOTAL_HEADER_LENGTH]
    bytes_content = bytes_message[TOTAL_HEADER_LENGTH:]

    header = parse_message_header(bytes_header)

    assert (
        len(bytes_content) > header.code.minimal_required_content()
    ), "Not enough bytes recived for content"
    content = parse_meesage_content(header.code, bytes_content)

    return Message(header, content)
