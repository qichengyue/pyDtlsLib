from socket import socket


class DTLSConnection(object):
    def __init__(self, dgram_socket, ip, port):
        self._socket = dgram_socket
        if isinstance(self._socket, socket.socket):
            raise TypeError('The first arg must be an instance of socket')
        self.ip = ip
        self.port = port


    def do_handshake(self):
