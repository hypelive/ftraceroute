from icmp import ICMP, socket


class ICMPv6(ICMP):
    AF = socket.AF_INET6
    TYPE = 128
    PACK_TYPE = None
    ID_ALIVE = None
    ID_DEAD = None

    def deconstruct_response(self, response):
        receive_packet, (hop_address, _) = response
        return receive_packet, hop_address
