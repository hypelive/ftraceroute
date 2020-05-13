import unittest
from debug import get_header_info, get_packet_info, icmp_header_parse


class TestDebug(unittest.TestCase):
    def test_send_packet(self):
        header = b'\x08\x00\xf6\xff\x00\x00\x01\x00'
        info = get_header_info(header)
        self.assertEqual(info.type_icmp, 8)
        self.assertEqual(info.icmp_checksum, 65526)
        self.assertEqual(info.identifier, 0)
        self.assertEqual(info.sequence, 1)
        self.assertEqual(info.code_icmp, 0)
        header = b'\x08\x00\x32\x3b\x00\x00\x01\x0011111111'
        info = get_header_info(header)
        self.assertEqual(info.type_icmp, 8)
        self.assertEqual(info.icmp_checksum, 15154)
        self.assertEqual(info.identifier, 0)
        self.assertEqual(info.sequence, 1)
        self.assertEqual(info.code_icmp, 0)

    def test_header_format_str(self):
        header = b'\x08\x00\x32\x3b\x00\x00\x01\x0011111111'
        self.assertEqual(icmp_header_parse(header, 12), '''
TTL: 12
Version icmp: 8
Code icmp: 0
Checksum icmp: 15154
Identifier: 0
Sequence number: 1
Data: b'11111111'
''')

    def test_recive_packet(self):
        pack = b'E\x00\x008\x00\x00\x00\x00\xfa\x01\xce\x8b\xbc\x80t\x0b' +\
            b'\xc0\xa8\x01\x05\x0b\x00\xf5\x00\x00\x00\x00\x00E\x00\x00' +\
            b'\x1cZ\x9f\x00\x00\x01\x01%\xcc\xc0\xa8\x01\x05\xd4\xc1' +\
            b'\xa3\x07\x08\x00\xf6\xfe\x00\x00\x01\x00'
        info = get_packet_info(pack)
        self.assertEqual(info.header_length, 69)
        self.assertEqual(info.explicit_notification, 0)
        self.assertEqual(info.total_length, 56)
        self.assertEqual(info.ip_identification, 0)
        self.assertEqual(info.fragment_offset, 0)
        self.assertEqual(info.time_to_live, 250)
        self.assertEqual(info.protocol, 1)
        self.assertEqual(info.header_checksum, 52875)
        self.assertEqual(info.source, 3162534923)
        self.assertEqual(info.destination, 3232235781)
