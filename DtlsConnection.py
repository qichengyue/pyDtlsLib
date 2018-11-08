import struct
from socket import socket

from Record import ClientHello, RecordContentType, HandshakeType


class DTLSConnection(object):
    def __init__(self, dgram_socket, ctx, ip, port):
        self._socket = dgram_socket
        if not isinstance(self._socket, socket):
            raise TypeError('The first arg must be an instance of socket')
        self.ctx = ctx
        self.ip = ip
        self.port = port

    def do_handshake(self):

        # Handshake States:
        # ClientHello1
        # ServerHelloVerifyRequest
        # ClientHello2
        # ServerHello
        #
        #

        max_retry = 5
        state = 'ClientHello1'
        for i in range(max_retry):
            if state == 'ClientHello1':
                client_hello = ClientHello(self.ctx)
                ba = bytearray()
                ba.extend(client_hello.get_record_bytes())
                ba[-2:] = struct.pack('>H', len(client_hello.get_payload_bytes()))  # fill up length segment
                ba.extend(client_hello.get_payload_bytes())
                self._socket.sendto(bytes(ba), (self.ip, self.port))

                server_response = self._socket.recv(1500)
                if (server_response[0] == struct.pack('>B', RecordContentType.Handshake.value)) \
                    and (server_response[13] == struct.pack('>B', HandshakeType.HelloVerifyRequest.value)):
                    state = 'ServerHelloVerifyRequest'
                    cookie_len = struct.unpack('>B', server_response[27])[0]
                    cookie = server_response[28:]
                else:
                    print(b'could not parse response for ClientHello1, response body:%s' % server_response)
                    state = 'ClientHello1'
                    continue

            if state == 'ServerHelloVerifyRequest':






