import socket
import sys

HOST = 'whois.ripe.net'
#HOST = 'whois.arin.net'
#HOST = 'whois.apnic.net'
#HOST = 'whois.lacnic.net'
#HOST = 'whois.afrinic.net'
PORT = 43

class WhoisInfo:
    TIMEOUT = 1

    def __init__(self, address: str):
        data = self._get_data(bytes(address, 'utf8'))
        self._init(data)

    def _get_data(self, address: bytes) -> list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
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

    def _init(self, data):
        for line in data:
            attr_separator = line.find(':')
            setattr(self, line[:attr_separator].strip(), line[attr_separator + 1:].strip())

    def get_property(self, name: str) -> str:
        if name in self.__dict__:
            return self.__dict__[name]