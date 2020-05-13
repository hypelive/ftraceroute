from icmp import ICMP, socket


class ICMPv4(ICMP):
    AF = socket.AF_INET
    TYPE = 8
    PACK_TYPE = 20
    ID_ALIVE = 24
    ID_DEAD = 52

    def deconstruct_response(self, response):
        receive_packet, (hop_address, _) = response
        return receive_packet, hop_address
