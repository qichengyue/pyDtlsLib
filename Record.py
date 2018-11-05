import random
import struct
from enum import Enum

from DTLS import DtlsVersion


def random_bytes_generator(n):
    result = bytearray()
    for i in range(n):
        result.append(random.randint(1, 255))

    return bytes(result)

class RecordContentType(Enum):
    Handshake = 0x16
    ChangeCipherSpec = 0x14
    ApplicationData = 0x17


class HandshakeType(Enum):
    ClientHello = 0x01
    HelloVerifyRequest = 0x03
    ServerHello = 0x02
    Certificate = 0x0b
    ServerKeyExchange = 0x0c
    ServerHelloDone = 0x0e
    ClientKeyExchange = 0x10
    NewSessionTicket = 0x04


class Record(object):
    def __init__(self, content_type, version):
        if isinstance(content_type, RecordContentType):
            raise TypeError('content_type must be a value of "RecordContentType"')

        self.content_type = content_type
        self.version = DtlsVersion.DTLSv1
        self.epoch = 0
        self.sequence_number = 0
        self.length = 0


class HandshakeProtocol(Record):
    def __init__(self, version):
        super(HandshakeProtocol, self).__init__(RecordContentType.Handshake, version)


class ChangeCipherSpecProtocol(Record):
    def __init__(self, version):
        super(ChangeCipherSpecProtocol, self).__init__(RecordContentType.ChangeCipherSpec, version)


class ApplicationDataProtocol(Record):
    def __init__(self, version):
        super(ApplicationDataProtocol, self).__init__(RecordContentType.ApplicationData, version)


class ClientHello(HandshakeProtocol):
    def __init__(self, version):
        super(ClientHello, self).__init__(version)

        self.payload = bytearray()
        self.payload.append(HandshakeType.ClientHello.value)
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes length, fill up later
        self.payload.extend(b'\x00\x00')        # 2 bytes message sequence, fill up later
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes fragment offset, fill up later
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes fragment length, fill up later
        self.payload.extend(struct.pack('>H', self.version.value))  # 2 bytes DTLS version
        self.payload.extend(random_bytes_generator(32))                # 32 random bytes
        self.payload.extend(b'\x00')            # 1 bytes session id length
        self.payload.extend(b'\x00')            # 1 bytes cookie length
        self.payload.extend(b'\x00\x00')        # 2 bytes cipher suite length
        self.payload.extend(b'All Cipher Suite')        # list all supported cipher suite




