import struct
from socket import socket

from CipherSuites import CipherSuites
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

        max_retry = 1
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
                if (server_response[0] == RecordContentType.Handshake.value
                        and (server_response[13] == HandshakeType.HelloVerifyRequest.value)):
                    state = 'ServerHelloVerifyRequest'
                    cookie_len = server_response[27]
                    cookie = server_response[28:]
                else:
                    print(b'could not parse response for ClientHello1, response body:%s' % server_response)
                    state = 'ClientHello1'
                    continue

            if state == 'ServerHelloVerifyRequest':
                message_sequence = 1
                client_hello = ClientHello(self.ctx, cookie=cookie, message_sequence=message_sequence)
                ba = bytearray()
                ba.extend(client_hello.get_record_bytes())
                ba[-2:] = struct.pack('>H', len(client_hello.get_payload_bytes()))  # fill up length segment
                ba.extend(client_hello.get_payload_bytes())
                self._socket.sendto(bytes(ba), (self.ip, self.port))
                server_hello = self._socket.recv(1024)
                assert server_hello[0] == 0x16
                assert server_hello[1:3] == b'\xfe\xff'     # support DTLSv1 only
                assert server_hello[13] == 0x02
                cipher_suite = CipherSuites(struct.unpack('>H', server_hello[60:62])[0])
                state = 'Certificate'

            if state == 'Certificate':
                is_certificate_complete = False
                resp = self._socket.recv(1500)
                assert resp[0] == 0x16
                assert resp[13] == HandshakeType.Certificate.value
                certificate_length = (struct.unpack('>BH', resp[14:17])[0] << 16) + struct.unpack('>BH', resp[14:17])[1]
                temp_length = 0     # already finished part length of the certificate
                certificate = bytearray(certificate_length)
                print('Certificate length resp:%s' % certificate_length)
                fragment_length = (struct.unpack('>BH', resp[22:25])[0] << 16) + struct.unpack('>BH', resp[22:25])[1]
                if fragment_length == certificate_length:
                    is_certificate_complete = True
                    certificate[0:] = resp[25:fragment_length]
                else:
                    offset = (struct.unpack('>BH', resp[19:22])[0] << 16) + struct.unpack('>BH', resp[19:22])[1]
                    certificate[offset:fragment_length] = resp[25:fragment_length]

                temp_length += fragment_length

                while not is_certificate_complete:
                    resp = self._socket.recv(1500)
                    assert resp[0] == 0x16
                    assert resp[13] == HandshakeType.Certificate.value
                    fragment_length = (struct.unpack('>BH', resp[22:25])[0] << 16) + struct.unpack('>BH', resp[22:25])[1]
                    temp_length += fragment_length
                    if temp_length == certificate_length:
                        is_certificate_complete = True
                    offset = (struct.unpack('>BH', resp[19:22])[0] << 16) + struct.unpack('>BH', resp[19:22])[1]
                    certificate[offset:fragment_length] = resp[25:fragment_length]

                state = 'ServerKeyExchange'
                print('Certificate length: %s' % len(certificate))
                print(b'Certificate: %s' % certificate)








