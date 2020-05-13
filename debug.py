import struct
from collections import namedtuple


recive_packet_info = namedtuple(
    'Packet_info',
    ['header_length',
     'explicit_notification',
     'total_length',
     'ip_identification',
     'fragment_offset',
     'time_to_live',
     'protocol',
     'header_checksum',
     'source',
     'destination',
     'header_info'])

send_header_info = namedtuple(
    'Header_info',
    ['type_icmp',
     'code_icmp',
     'icmp_checksum',
     'identifier',
     'sequence']
)

HEADER_LENGTH = {
    5: 20
}


def packet_parse(packet):
    info = get_packet_info(packet)
    return f'''
Version: {int(bin(info.header_length)[2:-4], 2)}
Header length: {HEADER_LENGTH[int(bin(info.header_length)[-4:], 2)]}
Explicit Congestion Notification: {info.explicit_notification}
Total length: {info.total_length}
IP Identification: {info.ip_identification}
Fragment offset: {info.fragment_offset}
Time to live: {info.time_to_live}
Protocol ICMP: {info.protocol}
Checksum ip: {info.header_checksum}
Source: {get_ip_address(info.source)}
Destination: {get_ip_address(info.destination)}
Version icmp: {info.header_info.type_icmp}
Code icmp: {info.header_info.code_icmp}
Checksum icmp: {info.header_info.icmp_checksum}
Identifier: {info.header_info.identifier}
Sequence number: {info.header_info.sequence}
Data: {str(packet[28:]) if len(packet) > 28 else ''}
'''


def get_packet_info(packet):

    return recive_packet_info._make([*struct.unpack(
        '!BBHHHBBHII',
        packet[:20]),
        get_header_info(packet[20:28])])


def get_ip_address(value):
    return (f'{value // 2**24}.{(value % 2**24) // 2**16}.' +
            f'{(value % 2**16) // 256}.{value % 256}')


def icmp_header_parse(header, ttl=255):
    info = get_header_info(header[:8])
    return f'''
TTL: {ttl}
Version icmp: {info.type_icmp}
Code icmp: {info.code_icmp}
Checksum icmp: {info.icmp_checksum}
Identifier: {info.identifier}
Sequence number: {info.sequence}
Data: {str(header[8:]) if len(header) > 8 else ''}
'''


def get_header_info(header):
    return send_header_info._make(struct.unpack('bbHHh', header[:8]))


def get_damp_packet(packet):
    packet_length = len(packet)
    print_border = 0
    damp = []
    while print_border < packet_length:
        numeric = hex(print_border)[2:]
        bytes_repr = []
        ascii_repr = []
        for i in range(print_border, print_border + 16):
            temp = packet[i: i + 1].hex()
            bytes_repr.append(temp or '  ')
            if temp == '0a' or temp == '0d' or temp == '0c' or temp == '0b':
                ascii_repr.append(' ')
                continue
            if temp != '':
                ascii_repr.append(chr(int(temp, 16)))
        damp.append('0'*(4 - len(numeric)) + numeric + '  ' +
                    ' '.join(bytes_repr) + ' ' + ''.join(ascii_repr))
        print_border += 16
    return '\n'.join(damp)


def get_parse_result(result, ttl=255):
    recieve_pack = result[2][1]
    parse_result = ''
    recieve_pack_parse = packet_parse(recieve_pack)
    parse_result += f'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
{get_damp_packet(result[2][0])}{icmp_header_parse(result[2][0], ttl)}
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
'''
    parse_result += f'''
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
{get_damp_packet(recieve_pack)}{recieve_pack_parse}
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
    return parse_result
