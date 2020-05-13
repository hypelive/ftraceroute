from icmp import ICMP
from icmp4 import ICMPv4
from icmp6 import ICMPv6
import unittest
from unittest.mock import MagicMock
import struct
import socket
import time


class TestTraceroute(unittest.TestCase):
    def test_checksum(self):
        header = struct.pack('BbHHh', ICMPv4.TYPE, 0, 0, 0, 1)
        data = b''
        checksum = ICMP.calculate_checksum(header + data)
        self.assertEqual(checksum, int(0xf6ff))
        header = struct.pack('BbHHh', ICMPv6.TYPE, 0, 0, 0, 1)
        data = b''
        checksum = ICMP.calculate_checksum(header + data)
        self.assertEqual(checksum, 32511)
        header = struct.pack('BbHHh', ICMPv4.TYPE, 0, 0, 0, 1)
        data = b'11111111'
        checksum = ICMP.calculate_checksum(header + data)
        self.assertEqual(checksum, int(0x323b))

    def test_create_pack(self):
        icmpv4 = ICMPv4('')
        pack = icmpv4.create_packet()
        self.assertEqual(b'\x08\x00\xf6\xff\x00\x00\x01\x00', pack)
        icmpv4 = ICMPv4('', size=50)
        pack = icmpv4.create_packet()
        self.assertEqual(b'\x08\x00\x32\x3b\x00\x00\x01\x0011111111', pack)
        icmpv6 = ICMPv6('')
        pack = icmpv6.create_packet()
        self.assertEqual(b'\x80\x00~\xff\x00\x00\x01\x00', pack)

    def test_send_packet_with_max_ttl_v4(self):
        get_response_mock = MagicMock(return_value=True)
        icmpv4 = ICMPv4('212.193.163.7')
        standart = ICMPv4.get_response
        ICMPv4.get_response = get_response_mock
        response = icmpv4.send_packet(50)
        self.assertTrue(response)
        icmpv4 = ICMPv4('173.194.73.138')
        response = icmpv4.send_packet(50)
        self.assertTrue(response)
        icmpv4 = ICMPv4('91.198.174.192')
        response = icmpv4.send_packet(50)
        self.assertTrue(response)
        ICMPv4.get_response = standart

    @unittest.skipUnless(socket.has_ipv6, 'Protocol is not available')
    def test_send_packet_with_max_ttl_v6(self):
        icmpv6 = ICMPv6('0:0:0:0:0:FFFF:5DBA:E1C1')
        standart = ICMPv6.get_response
        ICMPv6.get_response = MagicMock(return_value=True)
        try:
            response = icmpv6.send_packet(50)
        except OSError:
            self.skipTest('Protocol is not available')
        self.assertTrue(response)
        ICMPv6.get_response = standart

    def test_response_without_send(self):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.getprotobyname('icmp')) as icmp_socket:
            icmpv4 = ICMPv4('')
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
            self.assertEqual((None, None, (None, None)),
                             icmpv4.get_response(icmp_socket,
                                                 time.time(), None, 1))

    def test_send_packet(self):
        get_response_mock = MagicMock(return_value=True)
        standart = ICMPv4.get_response
        ICMPv4.get_response = get_response_mock
        icmpv4 = ICMPv4('173.194.73.138')
        for ttl in range(1, 31):
            try:
                self.assertTrue(icmpv4.send_packet(ttl))
            except socket.error:
                continue
        ICMPv4.get_response = standart

    def test_send_packets(self):
        send_packets_mock = MagicMock()
        host = '173.194.73.138'
        icmpv4 = ICMPv4('173.194.73.138')
        send_packets_mock.side_effect = [
            [('NonGoogle', None, None)], [(host, None, None)]]
        standart = ICMPv4.form_response
        ICMPv4.form_response = send_packets_mock
        response = icmpv4.form_response(1)
        self.assertNotEqual(response[0][0], host)
        response = icmpv4.form_response(50)
        self.assertEqual(response[0][0], host)
        ICMPv4.form_response = standart
