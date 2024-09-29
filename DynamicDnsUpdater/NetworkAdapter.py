import logging
import re
import netifaces # type: ignore
from netaddr import IPAddress # type: ignore
from typing import List, Optional
from .objects import IpData, Netstated
import subprocess

logging.basicConfig(level=logging.INFO)

class NetworkAdapter:
    name: str = None # Network Adapter name

    def __init__(self, name) -> None:
        self.name = name
    
    def getIpData(self) -> IpData:
        ipAddress = self.getIpAddress()
        ipAddress6 = self.getIpAddress6()
        return IpData(
            name=self.name,
            ip=ipAddress,
            ipv6=ipAddress6
        )
        

    def getGateway(self) -> Optional[str]:
        gws = netifaces.gateways()
        for gw in gws:
            try:
                gwstr: str = str(gw)
                if 'default' not in gwstr:
                    entries = gws[gw]
                    for entry in entries:
                        if self.name in entry[1]:
                            return entry[0]
            except:
                logging.error(f"getGateway => {gw}")
        # If this is hit, then it could not find the gateway using traditional means
        logging.info("Using fallback to get gateway")
        netst = self.parseNetstat(nic_name=self.name)
        routable = [line for line in netst if "G".lower() in line.flags.lower()]
        use_route: Netstated = next(iter(routable), None)
        if (use_route is not None):
            return use_route.gateway
        return None
    
    def getNetmask(self) -> Optional[str]:
        gw = self.getGateway()
        try:
            netmask = gw[:gw.rfind(".")+1]+"0"
            return netmask
        except:
            logging.error(f"getNetmask => {gw}")
            pass
        return None

    def getIpAddress(self) -> Optional[str]:
        try:
            iface = netifaces.ifaddresses(self.name)
            entry = iface[netifaces.AF_INET][0]
            return entry["addr"]
        except:
            pass
        return None
    
    def getIpAddress6(self) -> Optional[str]:
        try:
            iface = netifaces.ifaddresses(self.name)
            entry = iface[netifaces.AF_INET6][0]
            return entry["addr"]
        except:
            pass
        return None

    def getSubnet(self) -> Optional[str]:
        try:
            iface = netifaces.ifaddresses(self.name)
            entry = iface[netifaces.AF_INET][0]
            return entry["netmask"]
        except:
            pass
        return None

    def getCidr(self, subnet: str) -> Optional[str]:
        try:
            return IPAddress(subnet).netmask_bits()
        except:
            pass
        return None



    def parseNetstat(self, nic_name: str) -> List[Netstated]:
        netstat_out = subprocess.getoutput(f"netstat -r -n -e -4 | grep {nic_name}").split("\n")
        result = [s for s in netstat_out if s]
        if (len(result) == 0):
            return []
        else:
            entries: List[Netstated] = []
            for line in result:
                try:
                    columns = re.split(r'\s+', line)
                    entries.append(
                        Netstated(
                            destination=columns[0],
                            gateway=columns[1],
                            genmask=columns[2],
                            flags=columns[3],
                            metric=columns[4],
                            ref=columns[5],
                            use=columns[6],
                            iface=columns[7]
                        )
                    )
                except:
                    logging.exception("Failed to parse netstat")
            return entries

    
