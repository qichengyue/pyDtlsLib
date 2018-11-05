from socket import socket

from Record import ClientHello


class DTLSConnection(object):
    def __init__(self, dgram_socket, ctx, ip, port):
        self._socket = dgram_socket
        if isinstance(self._socket, socket.socket):
            raise TypeError('The first arg must be an instance of socket')
        self.ctx = ctx
        self.ip = ip
        self.port = port

    def do_handshake(self):
        client_hello = ClientHello(self.ctx)
        self._socket.send(client_hello.get_payload_bytes(), (self.ip, self.port))
