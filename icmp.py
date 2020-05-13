import debug as D
import socket
import time
import struct
import random


class ICMP:
    AF = None
    TYPE = None
    PACK_TYPE = None
    ID_ALIVE = None
    ID_DEAD = None

    def __init__(self, host, number=3,
                 timeout=1, size=42, debug=False):
        self.host = host
        self.packet_count = number
        self.timeout = timeout
        self.packet_size = size
        self.debug = debug

    @staticmethod
    def calculate_checksum(source_string):  # non inet
        checksum_packet = 0
        for count in range(0, (len(source_string) // 2) * 2, 2):
            checksum_packet += (
                source_string[count + 1])*256 + source_string[count]
        answer = ~checksum_packet
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def create_packet(self, identifier=0):  # non inet
        # ICMP type 8, Echo request message:
        # ICMPv6 in https://tools.ietf.org/html/rfc4443#section-4.1
        #
        # Type (8)	Code (8)	ICMP header checksum (16)  - 64 bit pack
        #   Identifier (16)	       Sequence number(16)
        #                Data (32)
        header = struct.pack('BbHHh', self.TYPE, 0, 0, identifier, 1)
        data = b'11' * ((self.packet_size - 42) // 2)
        icmp_header_checksum = ICMP.calculate_checksum(header + data)
        return struct.pack('BbHHh', self.TYPE, 0,
                           socket.htons(icmp_header_checksum),
                           identifier, 1) + data

    def recive_and_check_response(self, icmp_socket, send_identifier):
        response = None
        recived_identifier = None
        while (not response or
               recived_identifier != send_identifier):
            response = icmp_socket.recvfrom(1500)
            if struct.unpack('B', response[0][
                    self.PACK_TYPE:self.PACK_TYPE+1])[0] == 0:
                recived_identifier = struct.unpack(
                    'H', response[0][self.ID_ALIVE:self.ID_ALIVE+2])[0]
            else:
                recived_identifier = struct.unpack(
                    'H', response[0][self.ID_DEAD:self.ID_DEAD+2])[0]
        return response

    def get_response(self, icmp_socket, time_sent, sent_packet,
                     send_identifier):
        icmp_socket.settimeout(self.timeout)
        try:
            receive_packet, hop_address = self.deconstruct_response(
                self.recive_and_check_response(icmp_socket, send_identifier))
            total_time_ms = int((time.time() - time_sent) * 1000000) / 1000
        except socket.timeout:
            receive_packet = None
            hop_address = None
            total_time_ms = None
        return hop_address, total_time_ms, (sent_packet, receive_packet)

    def send_packet(self, ttl):
        with socket.socket(self.AF, socket.SOCK_RAW,
                           socket.getprotobyname('icmp')) as icmp_socket:
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            send_identifier = random.randint(0, 30000)
            packet = self.create_packet(send_identifier)
            icmp_socket.sendto(packet, (self.host, 0))
            response = self.get_response(icmp_socket, time.time(), packet,
                                         send_identifier)
        return response

    def send_packets(self, ttl):
        for _ in range(self.packet_count):
            yield self.send_packet(ttl)

    def form_response(self, ttl):
        response = ''
        packets = ''
        for result in self.send_packets(ttl):
            # result is hop_addr, time, (sent pack, rec pack)
            response += str(result[1]) + ' '
            if result[0]:
                hop_address = result[0]
                if self.debug:
                    packets += D.get_parse_result(result, ttl)
            else:
                hop_address = '-'
        return hop_address, response, packets

    def deconstruct_response(self, response):
        return None, None
