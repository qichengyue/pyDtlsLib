import struct
from socket import socket

from Record import ClientHello


class DTLSConnection(object):
    def __init__(self, dgram_socket, ctx, ip, port):
        self._socket = dgram_socket
        if not isinstance(self._socket, socket):
            raise TypeError('The first arg must be an instance of socket')
        self.ctx = ctx
        self.ip = ip
        self.port = port

    def do_handshake(self):
        client_hello = ClientHello(self.ctx)
        ba = bytearray()
        ba.extend(client_hello.get_record_bytes())
        ba[-2:] = struct.pack('>H', len(client_hello.get_payload_bytes()))  # fill up length segment
        ba.extend(client_hello.get_payload_bytes())
        self._socket.sendto(bytes(ba), (self.ip, self.port))

