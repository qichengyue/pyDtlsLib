import socket

from DTLSVersion import DtlsVersion
from DTLSContext import DTLSContext
from DtlsConnection import DTLSConnection

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = '172.22.134.1'
port = 4567

ctx = DTLSContext(DtlsVersion.DTLSv1)
dtls_connection = DTLSConnection(s, ctx, ip, port)
dtls_connection.do_handshake()
