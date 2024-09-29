import json
import subprocess
from .objects import IpInfo
from typing import Optional

class AddressInfo:
    """_summary_
        ip -4 -j -o addr show internet
    """
    interface: str
    init_values: IpInfo
    
        
    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.init_values = self.read()

    def read(self) -> Optional[IpInfo]:
        addrinfo = subprocess.getoutput(f"ip -4 -j -o addr show {self.interface}")
        jo = json.loads(addrinfo)
        if len(jo) == 1 and len(jo[0]["addr_info"]) == 1:
            details: dict = jo[0]["addr_info"][0]
            return IpInfo(
                interface=self.interface,
                dynamic=details.get("dynamic"),
                ttl=details.get("valid_life_time"),
                ip=details.get("local"),
                prefix=details.get("prefixlen")
            )
        return None