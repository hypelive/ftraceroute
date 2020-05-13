import socket
import argparse
import sys
import debug as D
from icmp4 import ICMPv4
from icmp6 import ICMPv6
from whois_info import WhoisInfo

ICMP_VERSION = {
    4: ICMPv4,
    6: ICMPv6
}

def print_result_default(ttl, address, response, whois_info= None):
    print('%-3d%-28s%-16s%-32s' % (ttl, address,
                                   response[0], response[1]))


def print_result_whois(ttl, address, response, whois_info: WhoisInfo):
    as_number = whois_info.get_property("origin")
    if as_number and as_number.startswith('AS'):
        as_number = as_number[2:]
    country = whois_info.get_property("country")
    if country and country.startswith('EU'):
        country = None
    whois_result = ", ".join(filter(lambda param: param, [whois_info.get_property("netname"), as_number, country]))
    if is_local(response[0]):
        whois_result = 'local'
    if whois_result:
        whois_result += '\r\n'
    print(f'{ttl}. {address}\r\n{whois_result}')


def is_local(address: str) -> bool:
    return (address.startswith('192.168.') or
            address.startswith('172.16.') or
            address.startswith('127.') or
            address.startswith('10.') or
            address.startswith('169.254.'))


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
    parser.add_argument('-c', '--classic', help='classic output',
                        action='store_true')
    parser.add_argument('site', help='trace to (name or IP of host)')
    args = parser.parse_args()

    try:
        host = socket.gethostbyname(args.site)
    except PermissionError:
        print('not enough permissions')
        exit(1)
    except socket.error:
        print(f'{host} is invalid')
        exit(1)
    title = f' trace to {args.site}({host}), max hops = {args.m}'
    version = 4
    if args.use_IPv6:
        version = 6

    print_function = print_result_whois
    if args.classic:
        WhoisInfo.TIMEOUT = args.timeout
        print_function = print_result_default 

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
        whois_info = None
        if not args.classic and response[1] != icmp_sender.UNDEFINED_ADDRESS_SYMBOL:
            whois_info = WhoisInfo(address)
        print_function(ttl, address, response, whois_info)
        if args.debug:
            sys.stderr.writelines(response[2])
        if response[0] == host:
            return 0


if __name__ == '__main__':
    main()
