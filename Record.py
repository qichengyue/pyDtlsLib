import random
import struct
from enum import Enum

from DTLSVersion import DtlsVersion


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
    def __init__(self, content_type, ctx, **args):
        if not isinstance(content_type, RecordContentType):
            raise TypeError('content_type must be a value of "RecordContentType"')

        self.ctx = ctx
        self.content_type = content_type
        self.version = ctx.version
        self.epoch = 0
        if 'message_sequence' in args:
            self.sequence_number = args['message_sequence']
        else:
            self.sequence_number = 0
        self.length = 0

    def get_record_bytes(self):
        ba = bytearray()
        ba.extend(struct.pack('>B', self.content_type.value))   # 1 byte content type
        ba.extend(struct.pack('>H', self.version.value))        # 2 bytes dtls version
        ba.extend(struct.pack('>H', self.epoch))                # 2 bytes epoch
        # 6 bytes sequence_number..
        ba.extend(struct.pack('>HI', self.sequence_number >> 32, self.sequence_number & 0x0000ffffffff))
        ba.extend(b'\x00\x00')     # the length is the whole left packet, to be filled up
        return bytes(ba)


class HandshakeProtocol(Record):
    def __init__(self, ctx, **args):
        super(HandshakeProtocol, self).__init__(RecordContentType.Handshake, ctx, **args)


class ChangeCipherSpecProtocol(Record):
    def __init__(self, ctx):
        super(ChangeCipherSpecProtocol, self).__init__(RecordContentType.ChangeCipherSpec, ctx)


class ApplicationDataProtocol(Record):
    def __init__(self, ctx):
        super(ApplicationDataProtocol, self).__init__(RecordContentType.ApplicationData, ctx)


class ClientHello(HandshakeProtocol):
    def __init__(self, ctx, **args):
        HandshakeProtocol.__init__(self, ctx, **args)

        self.payload = bytearray()
        self.cookie = b''

        self.payload.append(HandshakeType.ClientHello.value)    # 1 bytes handshake type
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes length, fill up later
        if 'message_sequence' in args:
            self.payload.extend(struct.pack('>H', args['message_sequence']))
        else:
            self.payload.extend(b'\x00\x00')        # 2 bytes message sequence, fill up later
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes fragment offset, fill up later
        self.payload.extend(b'\x00\x00\x00')    # 3 bytes fragment length(= payload length - 12), fill up later
        self.payload.extend(struct.pack('>H', self.ctx.get_dtls_version().value))  # 2 bytes DTLS version
        self.payload.extend(random_bytes_generator(32))             # 32 random bytes
        self.payload.extend(b'\x00')            # 1 byte session id length
        if 'cookie' in args:
            self.cookie = args['cookie']
            self.payload.extend(struct.pack('>B', len(self.cookie)))     # 1 byte cookie length
            self.payload.extend(self.cookie)
        else:
            self.payload.extend(b'\x00')            # 1 byte cookie length
        self.payload.extend(b'\x00\x00')        # 2 bytes cipher suite length
        cipher_suite_bytes = self.ctx.get_cipher_suites_bytes()
        self.payload.extend(cipher_suite_bytes)        # all supported cipher suite
        self.payload.extend(ctx.compression_methods_length)     # 1 bytes compression length
        self.payload.extend(ctx.compression_methods)

        extension = [
            0x00, 0x0b,     # Type: ec_point_formats_type(11)
            0x00, 0x04,     # length = 4
            0x03,           # EC point formats length = 3
            0x00, 0x01, 0x02,   # Elliptic curves point formats

            0x00, 0x0a,     # Type: supported groups
            0x00, 0x1c,     # length = 28
            0x00, 0x1a,     # Supported group list length
            0x00, 0x17, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x1b,
            0x00, 0x18, 0x00, 0x1a, 0x00, 0x16, 0x00, 0x0e,
            0x00, 0x0d, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x09,
            0x00, 0x0a,

            0x00, 0x23,     # Type: SessionTicket TLS
            0x00, 0x00,     # length 0

            0x00, 0x0f,     # Type: heartbeat
            0x00, 0x01,     # Length 1
            0x01,           # Peer allowed to send requests
        ]

        self.payload.extend(struct.pack('>H', len(extension)))  # fill up 2 bytes extension length
        self.payload.extend(extension)
        self.payload[48+len(self.cookie):50+len(self.cookie)] = struct.pack('>H', len(cipher_suite_bytes))  # fill up cipher suite length
        total_payload_length = len(self.payload)
        fragment_length = total_payload_length - 12
        # Convert length to 3 bytes, fragment length = total_payload_length - 12
        self.payload[9:12] = struct.pack('>BH', fragment_length >> 16, fragment_length & 0x00ffff)
        self.payload[1:4] = self.payload[9:12]  # fill up client hello part total length

    def get_payload_bytes(self):
        return bytes(self.payload)







