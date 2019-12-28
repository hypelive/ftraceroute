import unittest
from debug import send_header_parse, packet_parse


class TestDebug(unittest.TestCase):
    def test_send_packet(self):
        header = b'\x08\x00\xf6\xff\x00\x00\x01\x00'
        self.assertEqual(send_header_parse(header, 1), '''
TTL: 1
Version icmp: 8
Code icmp: 0
Checksum icmp: 65526
Identifier: 0
Sequence number: 1
Data: 
''')
        header = b'\x08\x00\x32\x3b\x00\x00\x01\x0011111111'
        self.assertEqual(send_header_parse(header, 12), '''
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
        self.assertEqual(packet_parse(pack), '''
Header length: 69
Explicit Congestion Notification: 0
Total length: 56
IP Identification: 0
Fragment offset: 0
Time to live: 250
Protocol: 1
Checksum ip: 35790
Source: 188.128.116.11
Destination: 192.168.1.5
Version icmp: 11
Code icmp: 0
Checksum icmp: 245
Identifier: 0
Sequence number: 0
Data: ''' + str(b'E\x00\x00\x1cZ\x9f\x00\x00\x01\x01%\xcc\xc0\xa8\x01\x05' +
                b'\xd4\xc1\xa3\x07\x08\x00\xf6\xfe\x00\x00\x01\x00') + '\n')
