import socket

from OpenSSL import SSL
from OpenSSL._util import lib

DTLSv1_METHOD = 7
DTLSv12_METHOD = 8

SSL.Context._methods[DTLSv1_METHOD] = lib.DTLSv1_client_method
SSL.Context._methods[DTLSv12_METHOD] = lib.DTLS_client_method

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ctx = SSL.Context(DTLSv12_METHOD)
con = SSL.Connection(ctx, s)

con.connect(('172.22.134.1', 4567))
con.do_handshake()
con.send(b'abc')

print('Socket FD: %s' % s.fileno())
print('Cipher:', con.get_cipher_name(), 'Protocol:', con.get_protocol_version_name())
