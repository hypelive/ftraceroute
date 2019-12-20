import Ftraceroute as Traceroute
import unittest
import struct
import socket
import time

ICMP_types = {
    4 : 8,
    6 : 128 }

ICMP_sockets = {    # need to tests without internet
    4 : socket.AF_INET,
    6 : socket.AF_INET6 }


class TestTraceroute(unittest.TestCase):
    def test_checksum(self):
        header = struct.pack('BbHHh', ICMP_types[4], 0, 0, 0, 1)
        data = b''
        checksum = Traceroute.calculate_checksum(header + data)
        self.assertEqual(checksum, int(0xf6ff))
        header = struct.pack('BbHHh', ICMP_types[6], 0, 0, 0, 1)
        data = b''
        checksum = Traceroute.calculate_checksum(header + data)
        self.assertEqual(checksum, 32511)
        header = struct.pack('BbHHh', ICMP_types[4], 0, 0, 0, 1)
        data = b'11111111'
        checksum = Traceroute.calculate_checksum(header + data)
        self.assertEqual(checksum, int(0x323b))

    def test_create_pack(self):
        pack = Traceroute.create_packet()
        self.assertEqual(b'\x08\x00\xf6\xff\x00\x00\x01\x00', pack)
        pack = Traceroute.create_packet(50)
        self.assertEqual(b'\x08\x00\x32\x3b\x00\x00\x01\x0011111111', pack)
        pack = Traceroute.create_packet(version=6)
        self.assertEqual(b'\x80\x00~\xff\x00\x00\x01\x00', pack)

    def test_send_packet_with_max_ttl_v4(self):
        host = socket.gethostbyname('e1.ru')
        response = Traceroute.send_packet(host, 50)
        self.assertEqual(response[0], host)
        host = socket.gethostbyname('google.com')
        response = Traceroute.send_packet(host, 50)
        self.assertEqual(response[0], host)
        host = socket.gethostbyname('ru.wikipedia.org')
        response = Traceroute.send_packet(host, 50)
        self.assertEqual(response[0], host)

    #def test_send_packet_with_max_ttl_v6(self):
    #    host = '0:0:0:0:0:FFFF:5DBA:E1C1'
    #    response = Traceroute.send_packet(host, 50, version=6)
    #    self.assertEqual(response[0], host) 

    def test_response_without_send(self):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.getprotobyname('icmp')) as icmp_socket:
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
            self.assertEqual((None, None, (None, None)), Traceroute.get_response(
                              icmp_socket, time.time(), None))

    def test_send_packet(self):
        host = socket.gethostbyname('google.com')
        for ttl in range(1, 31):
            try:
                Traceroute.send_packet(host, ttl)
            except socket.timeout:
                continue
            except socket.error:
                assert False
        assert True

    def test_send_packets(self):
        host = socket.gethostbyname('google.com')
        response = Traceroute.form_response(host, 1)
        self.assertNotEqual(response[0], host)
        response = Traceroute.form_response(host, 30)
        self.assertEqual(response[0], host)
