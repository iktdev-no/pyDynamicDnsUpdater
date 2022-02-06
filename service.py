from typing import Optional
import json
import netifaces
import dns.resolver
import time
import datetime
import subprocess
import sys
from termcolor import colored as tcolor
from domeneshop import Client
from threading import Thread
import signal

token="{TOKEN}"
secret="{SECRET}"

runDhcp = False
terminate = False
threads = []
delay_minutes = 15

modify = True # For testing, Set false if actual updates should not be done
debug = True # Set to true if something is failing

class DomainDto:
    __domain: str = None
    __FQDN = list()
    
    def __init__(self, domain_entry):
        self.__domain = domain_entry["parent"]
        self.__FQDN = domain_entry["FQDN"]

    def getDomain(self):
        return self.__domain
    
    def getFQDN(self):
        return self.__FQDN



class Printy:
    @staticmethod
    def getTimeAndDate():
        now = datetime.datetime.now()
        return now.strftime("%d.%m.%Y %H:%M:%S")

    @staticmethod
    def info(values):
        sys.stdout.write("INFO\t {}".format(values))
        sys.stdout.write("\n")
        
    @staticmethod
    def success(values):
        sys.stdout.write(tcolor("SUCCESS\t {}".format(values), "green"))
        sys.stdout.write("\n")

    @staticmethod
    def warn(values):
        sys.stdout.write(tcolor("WARN\t {}".format(values), "yellow"))
        sys.stdout.write("\n")
    
    @staticmethod
    def debug(values):
        if (debug == True):
            sys.stdout.write(tcolor("DEBUG\t {}".format(values), "blue"))
            sys.stdout.write("\n")

    @staticmethod
    def error(values):
        sys.stderr.write(tcolor("ERROR\t {}".format(values), "red"))
        sys.stdout.write("\n")
        
        
class Lookup:
    __useIPv4 = True
    __useIPv6 = True
    __resolver = None
    def __init__(self, ipv4: bool, ipv6: bool):
        self.__useIPv4 = ipv4
        self.__useIPv6 = ipv6
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ '151.249.124.1', '2a01:5b40:ac1::1' ] # Using ns1.hyp.net from domeneshop
        self.__resolver = resolver
        
    def __lookup(self, domain, records):
        domainIp = None
        try:
            ips = [s.to_text() for s in records]
            if (len(ips) > 0):
                domainIp = ips[0] # Only use the first one, no round robin DNS supported # Should only be one record
        except:
            Printy.error("Could not find Domain {} with a IPv4 address".format(domain))
        return domainIp
    
    def __ipv4(self, domain):
        if (self.__useIPv4 == False):
            return None
        try:
            records = self.__resolver.resolve(domain, 'A')
            return self.__lookup(domain, records)
        except Exception as e:
            print(e)
            return None
    
    def __ipv6(self, domain):
        if (self.__useIPv6 == False):
            return None
        try:
            records = self.__resolver.resolve(domain, 'AAAA')
            return self.__lookup(domain, records)
        except Exception as e:
            print(e)
            return None
    
    
    def getByDomain(self, domain):
        return {
            "ipv4": self.__ipv4(domain),
            "ipv6": self.__ipv6(domain)
        }
        

class Registery:
    __client = None
    __domain_id: int = None
    __domain = None
    
    def __init__(self, domain: str, token: str, secret: str):
        self.__client = Client(token, secret)
        self.__domain_id = self.__getDomainId(domain)
        self.__domain = domain
   
    def __getDomainId(self, domain: str) -> Optional[int]:
        domains = self.__client.get_domains()
        record = next(filter(lambda entry: entry['domain'] == domain, domains))
        if record is not None:
            return record['id']
        else:
            return None   
    
    class Record:
        __client = None
        __domain_id: int = None
        __recordType = None # Ex: A = IPv4, AAAA = IPv6
        __domain: str = None
        
        
        def __init__(self, client, domain: str, domain_id: int, recordType: str):
            self.__client = client
            self.__domain_id = domain_id
            self.__recordType = recordType
            self.__domain = domain
            
        # If parent/root domain is desired, pass "@", will only return first entry
        def __recordId(self, path: str) -> Optional[int]:
            records = self.__client.get_records(self.__domain_id)
            entries = list(filter(lambda entry: entry["host"] == path and entry["type"] == self.__recordType, records))
            if (len(entries) == 0):
                Printy.error("No {} Record present".format(self.__recordType))
                return None
            else:
                return entries[0]['id']
        
        # 
        # path: For Parent/Root "@"
        # destination: IP address or FQDN
        def __setRecord(self, path: str, destination):
            record_Id = self.__recordId(path)
            record = { "host": path, "ttl": 3600, "type": self.__recordType, "data": destination }

            if (modify != True):
                Printy.warn("Aborting changes \tModify is set to False")
                return

            if (record_Id is not None):
                try:
                    Printy.info("Updating Domain: {} @ {}, on {} @ {}, with record {}".format(self.__domain, self.__domain_id, path, record_Id, record))
                    self.__client.modify_record(self.__domain_id, record_Id, record)
                except Exception as e:
                    Printy.error("Failed to update Record")
                    print(e)
            else:
                try:
                    Printy.info("Updating Domain: {}, with record {}".format(self.__domain, record))
                    self.__client.create_record(self.__domain_id, record)
                except Exception as e:
                    Printy.error("Failed to create Record")
                    print(e)

        def changeRecord(self, FQDN: str, destination: str):
            Printy.debug("FQDN: {}, Destination: {}, Domain: {}".format(FQDN, destination, self.__domain))
            if (FQDN == self.__domain):
                Printy.debug("FQDN: {}, == Domain: {}".format(FQDN, self.__domain))
                self.__setRecord("@", destination)
            else:
                # Strip out parent domain here
                domain_pos = FQDN.rfind(self.__domain)
                if (domain_pos > 0):
                    path = FQDN[0:domain_pos-1]
                    Printy.debug("FQDN: {}, !== Domain: {}, Path: {}".format(FQDN, self.__domain, path))
                    self.__setRecord(path, destination)

        def getRecordId(self, path: str):
            return self.__recordId(path)
        
    def OnARecord(self) -> Record:
        return self.Record(self.__client, self.__domain, self.__domain_id, 'A')
        
    def OnAAAARecord(self) -> Record:
        return self.Record(self.__client, self.__domain , self.__domain_id, 'AAAA')
    
    def getDomainId(self):
        return self.__domain_id
    def getDomain(self):
        return self.__domain
        
        
class Ipy: 
    
    def __interface(self, name: str):
        iface = None
        try:
            iface = netifaces.ifaddresses(name)
        except Exception as e:
            print(e)
        return iface
        
    def __ipv4(self, iface) -> Optional[str]:
        if (iface is not None):
            return (iface[netifaces.AF_INET][0]["addr"])
        else:
            return None
        
    def __ipv6(self, iface) -> Optional[str]:
        if (iface is not None):
            return (iface[netifaces.AF_INET6][0]["addr"]).split("%")[0]
        else:
            return None
        
    def __ipv4_private(self, ip: str) -> bool:
        privateRange = [ "192", "10", "172" ]        
        if ("." not in ip):
            return False
        firstBlock = ip.split(".")[0]
        return firstBlock in privateRange
    
    def __ipv6_private(self, ip: str) -> bool:
        if (":" not in ip):
            return False
        if (ip.split(":")[0] == "fe80"): # Checks if it is link local
            return True
        else:
            return False
        
    def isPrivate(self, ip: str) -> bool:
        if (":" not in ip):
            return self.__ipv4_private(ip)
        else:
            return self.__ipv6_private(ip)
        
    def hasIPv4(self, name: str) -> bool:
        return self.__ipv4(self.__interface(name))
    def hasIPv6(self, name: str) -> bool:
        return self.__ipv6(self.__interface(name))

    def requestDHCP(self, name: str) -> bool:
        if (runDhcp is False):
            return
        dh = subprocess.Popen(["dhclient", "-i", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = dh.communicate()

        if (err != None or len(err.decode("utf-8")) > 0):
            Printy.error(err)
        if (out == None or len(out.decode("utf-8")) >= 0):
            Printy.info(out)
        Printy.info("Waiting 60 sec, for route to be ready..")
        time.sleep(60)
        
    def getIPv4(self, name: str) -> Optional[str]:
        return self.__ipv4(self.__interface(name))
    
    def getIPv6(self, name: str) -> Optional[str]:
        return self.__ipv6(self.__interface(name))

def signal_handler(sig, frame):
    global terminate
    terminate = True 

class Service:
    
    def __init__(self):
        global threads
        
        signal.signal(signal.SIGINT, signal_handler)
        
        Printy.info("Starting service")
        references = json.load(open("reference.json"))
        
        global runDhcp
        runDhcp = references["dhcp"]
        
        adapters = references["adapter"]
        for device in adapters:
            domains = self.__toDomainList(device["domains"])
            
            thread = Thread(
                target=self.watch,
                args=(device["interface"], domains, device["ipv4"], device["ipv6"])
            )
            threads.append(thread)
            Printy.info("Creating thread for interface: {}".format(device["interface"]))
        
    def __toDomainList(self, __item):
        domainList = []
        for item in __item:
            domainItem = DomainDto(item)
            domainList.append(domainItem)
        return domainList
    
    def start(self):
        for instance in threads:
            instance.start()
    
    def watch(self, interface: str, domains, ipv4: bool, ipv6: bool):
        registeryList = []
        for domain in domains:
            registery = Registery(domain.getDomain(), token, secret)
            regisertyItem = {
                "domain": domain,
                "registery": registery
            }
            registeryList.append(regisertyItem)            
        
        lookup = Lookup(ipv4, ipv6)
        ipy = Ipy()
        
        iterationLock = None
        
        while terminate != True:
            if (iterationLock is not None and iterationLock > time.time()):
                time.sleep(60)
                continue
                
            
            # Checks if the interface has a valid IP
            if (ipv4 and ipy.hasIPv4(interface) == False):
                Printy.debug("No IPv4 found on interface {}".format(interface))
                ipy.requestDHCP(interface)
            
            currentIPv4 = ipy.getIPv4(interface)
            currentIPv6 = ipy.getIPv6(interface)
            
            for instance in registeryList:
                domainItem: DomainDto = instance["domain"]
                domain: str = domainItem.getDomain()
                for FQDN in domainItem.getFQDN():
                    Printy.debug("Looking up {} on interface {}".format(FQDN, interface))
                    record = lookup.getByDomain(FQDN)
                    
                    if (ipv4 == True and currentIPv4 is not None and ipy.isPrivate(currentIPv4) == False):
                        if (currentIPv4 == record["ipv4"]):
                            Printy.info("{} @ {} is OK!".format(FQDN, currentIPv4))
                        else:
                            registery: Registery = instance["registery"]
                            registery.OnARecord().changeRecord(FQDN, currentIPv4)
                    

                    if (ipv6 == True and currentIPv6 is not None and ipy.isPrivate(currentIPv6) == False):
                        if (currentIPv6 == record["ipv6"]):
                            Printy.info("{} @ {} is OK!".format(FQDN, currentIPv6))
                        else:
                            registery: Registery = instance["registery"]
                            registery.OnAAAARecord().changeRecord(FQDN, currentIPv6)
                            
            iterationLock = time.time() + datetime.timedelta(minutes=delay_minutes).seconds
            Printy.debug("Next check will occur @ {}".format(datetime.datetime.fromtimestamp(iterationLock).strftime("%d.%m.%Y %H:%M")))
            
            
        Printy.info("Exited watch on interface {}".format(interface))
            
if (__name__ == "__main__"):
    service = Service()
    service.start()
                    
                
                    
                    
            
        
        


