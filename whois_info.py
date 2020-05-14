import socket
import sys

RIPE_HOST = 'whois.ripe.net'
ARIN_HOST = 'whois.arin.net'
APNIC_HOST = 'whois.apnic.net'
LACNIC_HOST = 'whois.lacnic.net'
AFRINIC_HOST = 'whois.afrinic.net'
PORT = 43

class WhoisInfo:
    TIMEOUT = .5
    HOSTS = [RIPE_HOST, ARIN_HOST, APNIC_HOST, LACNIC_HOST, AFRINIC_HOST]
    HOST_POINTER = 0
    IMPORTANT_KEYS = ["origin", "country", "netname"]

    def __init__(self, address: str):
        initial_host_pointer = self.HOST_POINTER
        self.info_count = 0
        self.whois_dict = None
        while True:
            data = self._get_data(bytes(address, 'utf8'))
            current_whois_dict = self._get_dict(data)
            current_info_count = self.get_dict_info_count(current_whois_dict)
            if current_info_count > self.info_count:
                self.whois_dict = current_whois_dict
                self.info_count = current_info_count
            if self.info_count == len(self.IMPORTANT_KEYS):
                break
            else:
                self.HOST_POINTER = (self.HOST_POINTER + 1) % len(self.HOSTS)
                if self.HOST_POINTER == initial_host_pointer:
                    break 

    def _get_data(self, address: bytes) -> list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.HOSTS[self.HOST_POINTER], PORT))
        if not address.endswith(b'\r\n'):
            address += b'\r\n'
        s.sendall(address)
        s.settimeout(self.TIMEOUT)
        result = []
        data = ' '
        while data:
            try:
                data = s.recv(1024).decode(encoding='utf8', errors='ignore')
            except socket.timeout:
                break
            for line in data.split('\n'):
                if line.startswith('%') or line.startswith('#') or line.strip() == '':
                    continue
                result.append(line)
        return result      

    def _get_dict(self, data):
        result = dict()
        for line in data:
            attr_separator = line.find(':')
            result[line[:attr_separator].strip().lower()] = line[attr_separator + 1:].strip()

        if 'originas' in result:
            result['origin'] = result['originas']
        return result

    def get_dict_info_count(self, whois_dict):
        return sum(map(lambda key: 1 if key in whois_dict else 0, self.IMPORTANT_KEYS))

    def get_property(self, name: str) -> str:
        if self.whois_dict and name in self.whois_dict:
            return self.whois_dict[name]