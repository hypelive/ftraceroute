import socket
import struct
import time
import argparse
import sys
import debug as D

ICMP_types = {
    4 : 8,
    6 : 128 }

ICMP_sockets = {
    4 : socket.AF_INET,
    6 : socket.AF_INET6 }

packet_location_diapasons = {    # type 0 is when we find end host
    0 : (20, 28),
    8 : (48, 56) }


def calculate_checksum(source_string):
    checksum_packet = 0
    for count in range(0, (len(source_string) // 2) * 2, 2):
        checksum_packet += (
                        source_string[count + 1])*256 + source_string[count]
    answer = ~checksum_packet
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(packet_size=42, version=4):
    # ICMP type 8, Echo request message:   
    # ICMPv6 in https://tools.ietf.org/html/rfc4443#section-4.1 
    #
    # Type (8)	Code (8)	ICMP header checksum (16)  - 64 bit pack - 8 byte
    #   Identifier (16)	       Sequence number(16)
    #                Data (32)
    header = struct.pack('BbHHh', ICMP_types[version], 0, 0, 0, 1)
    data = b'11' * ((packet_size - 42) // 2)
    icmp_header_checksum = calculate_checksum(header + data)
    return struct.pack('BbHHh', ICMP_types[version], 0,
                       socket.htons(icmp_header_checksum), 0, 1) + data


def get_response(icmp_socket, time_sent, sent_packet, timeout=1):
    icmp_socket.settimeout(timeout)
    try:
        receive_packet, (hop_address, _) = icmp_socket.recvfrom(1024)
        total_time_ms = int((time.time() - time_sent) * 1000000) / 1000
    except socket.timeout:
        receive_packet = None
        hop_address = None
        total_time_ms = None
    return hop_address, total_time_ms, (sent_packet, receive_packet)


def send_packet(host, ttl, timeout=1, packet_size=42, version=4):
    with socket.socket(ICMP_sockets[version], socket.SOCK_RAW,
                       socket.getprotobyname('icmp')) as icmp_socket:
        icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        packet = create_packet(packet_size, version)
        icmp_socket.sendto(packet, (host, 0))
        response = get_response(icmp_socket, time.time(), packet, timeout)
    return response


def send_packets(host, ttl, packet_count=3, timeout=1, packet_size=42,
                 version=4):
    for _ in range(packet_count):
        yield send_packet(host, ttl, timeout, packet_size, version)


def form_response(host, ttl, packet_count=3, timeout=1, packet_size=42,
                  version=4, debug=False):
    response = ''
    packets = ''
    for result in send_packets(host, ttl, packet_count, timeout, packet_size,
                               version):
        # result is hop_addr, time, (sent pack, rec pack)
        response += str(result[1]) + ' '
        if result[0]:
            hop_address = result[0]
            if debug:
                print(D.get_parse_result(result))
        else:
            hop_address = '-'
    return hop_address, response, packets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', help='timeout (seconds)',
                        default=1, type=float)
    parser.add_argument('-n', '--number', help='how much send packets '
                                               'with some TTL',
                        default=3, type=int)
    parser.add_argument('-m',  help='max ttl(max hops)', default=30, type=int)
    parser.add_argument('-s', '--size', help='packet size',
                        default=42, type=int)
    parser.add_argument('-r','--no_resolve', help='show result:'
                                   ' without -r : name with IP,'
                                   ' with -r : only IP', action='store_true')
    parser.add_argument('-6', '--use_IPv6', help='use IPv6', action='store_true')                               
    parser.add_argument('-d', '--debug', help='debug mode',
                        action='store_true')                            
    parser.add_argument('site', help='trace to (name or IP of host)')
    args = parser.parse_args()

    host = socket.gethostbyname(args.site)
    title = ' trace to {}({}), max hops = {}'.format(args.site, host, args.m)
    version = 4
    if args.use_IPv6:
        version = 6

    print('-' * len(title) + '-')
    print(title)
    print('-' * len(title) + '-')

    for ttl in range(1, args.m + 1):
        response = form_response(host, ttl, args.number,
                                    args.timeout, args.size,
                                    version, args.debug)
        address = response[0]
        if not args.no_resolve:
            try:
                address = socket.gethostbyaddr(response[0])[0]
            except socket.error:
                pass 
        print('%-3d%-28s%-16s%-32s' % (ttl, address,
                                       response[0], response[1]))
        if args.debug:
            sys.stderr.writelines(response[2])
        if response[0] == host:
            return 0


if __name__ == '__main__':
    main()
