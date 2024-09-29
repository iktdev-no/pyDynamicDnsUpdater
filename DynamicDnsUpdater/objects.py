from datetime import datetime
from typing import List

class Auth:
    token: str | None
    secret: str | None

    def __init__(self, token, secret) -> None:
        self.token = token
        self.secret = secret

class DDNSEntry:
    interface: str
    ipv4: bool
    ipv6: bool
    domains: List[str]

    def __init__(self, interface: str, ipv4: bool = True, ipv6: bool = False, domains: List[str] = []) -> None:
        self.interface = interface
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.domains = domains



class LookupResult:
    domain: str | None = None
    ip: str | None = None

    def __init__(self, domain: str, ip: str) -> None:
        self.domain = domain
        self.ip = ip

class IpData:
    name: str = None # Network Adapter name
    ip: str = None
    ipv6: str = None
    timeOfCreated: str = "Never set!"

    def __init__(self, name: str = None, ip: str = None, ipv6: str = None) -> None:
        self.name = name
        self.ip = ip
        self.ipv6 = ipv6
        self.timeOfCreated = datetime.now().strftime("%H:%M:%S %d.%m.%Y")

    def isValid(self) -> bool:
        """Checks if fields are valid/assigned

        Returns:
            bool: Returns true if all is valid or/and assigned
        """
        if (
            self.ip == None or
            self.ipv6 == None
        ):
            return False
        else:
            return True
        
    def __str__(self):
        return "\n{}\n\t{}\n\t{}\t/{}\n\t{}\n\t{}".format(self.name, self.ip, self.ipv6, self.timeOfCreated)

class IpInfo:
    interface: str = None
    is_dynamic: bool = False
    valid_life_time_in_sec: int = 0
    ip_address: str = None
    ip_address_prefix: str = None
    
    def __init__(self, interface: str, dynamic: bool, ttl: int, ip: str, prefix: str) -> None:
        self.interface = interface
        self.is_dynamic = dynamic
        self.valid_life_time_in_sec = ttl
        self.ip_address = ip
        self.ip_address_prefix = prefix
    def __str__(self):
        return "\tIPv4 => {},\n\t Prefix => {},\n\t isDHCP => {},\n\t TTL => {}\n".format(self.ip_address, self.ip_address_prefix, self.is_dynamic, self.valid_life_time_in_sec())
    

class Netstated:
    destination: str = None
    gateway: str = None
    genmask: str = None
    flags: str = None
    metric: str = None
    ref: str = None
    use: str = None
    iface: str = None

    def __init__(self, destination, gateway, genmask, flags, metric, ref, use, iface) -> None:
        self.destination = destination
        self.gateway = gateway
        self.genmask = genmask
        self.flags = flags
        self.metric = metric
        self.ref = ref
        self.use = use
        self.iface = iface

class RecordNotFoundException(Exception):
    message: str | None
    def __init__(self, message) -> None:
        self.message = message

class NotAValidIpException(Exception):
    message: str | None
    def __init__(self, message) -> None:
        self.message = message        