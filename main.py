import socket
import argparse
import sys
import debug as D
from icmp4 import ICMPv4
from icmp6 import ICMPv6

ICMP_VERSION = {
    4: ICMPv4,
    6: ICMPv6
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout',
                        help='timeout to packet (seconds)',
                        default=1, type=float)
    parser.add_argument('-n', '--number',
                        help='number of packets with same ttl',
                        default=3, type=int)
    parser.add_argument('-m',  help='max ttl(max hops)', default=30, type=int)
    parser.add_argument('-s', '--size', help='packet size',
                        default=42, type=int)
    parser.add_argument('-r', '--no-resolve',
                        help="don't resolve address to hostname",
                        action='store_true')
    parser.add_argument('-6', '--use_IPv6',
                        help='use IPv6', action='store_true')
    parser.add_argument('-d', '--debug', help='debug mode',
                        action='store_true')
    parser.add_argument('site', help='trace to (name or IP of host)')
    args = parser.parse_args()

    host = socket.gethostbyname(args.site)
    title = f' trace to {args.site}({host}), max hops = {args.m}'
    version = 4
    if args.use_IPv6:
        version = 6

    print('-' * len(title) + '-')
    print(title)
    print('-' * len(title) + '-')

    icmp_sender = ICMP_VERSION[version](
        host, args.number, args.timeout, args.size, args.debug)

    for ttl in range(1, args.m + 1):
        response = icmp_sender.form_response(ttl)
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
