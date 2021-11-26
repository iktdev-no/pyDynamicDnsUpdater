import netifaces
import dns.resolver
import time
import datetime
import subprocess
import sys
from termcolor import colored as tcolor
from domeneshop import Client

interface = 'internet'

ddns_prefix = "standalone"
ddns = '{}.skjonborg.no'.format(ddns_prefix)

dns_ipv4 = None
dns_ipv6 = None

ipv4_lock = None
ipv6_lock = None

token="{TOKEN}"
secret="{SECRET}"

def getTimeAndDate():
    now = datetime.datetime.now()
    return now.strftime("%d.%m.%Y %H:%M:%S")

def info(values):
    sys.stdout.write("INFO\t {}".format(values))
    #sys.stdout.write("[{}]: INFO\t {}".format(getTimeAndDate(), values))
    sys.stdout.write("\n")

def success(values):
    sys.stdout.write(tcolor("SUCCESS\t {}".format(values), "green"))
    sys.stdout.write("\n")

def warn(values):
    sys.stdout.write(tcolor("WARN\t {}".format(values), "yellow"))
    sys.stdout.write("\n")

def error(values):
    sys.stderr.write(tcolor("ERROR\t {}".format(values), "red"))
    sys.stdout.write("\n")

class registery:
    client = None
    domain_id = None

    def __init__(self):
        self.__token = token
        self.__secret = secret
        self.client = Client(token, secret)
        self.domain_id = self.getDomainId()
        if (self.domain_id == None):
            error("Could not find Domain Id")
            exit(1)


    def getDomainId(self):
        domain = self.client.get_domains()[1] # Correct domain is nr 2 (and index starts at 0)
        return domain['id']

    # IPv4
    def getIpv4RecordId(self):
        domainRecords = self.client.get_records(self.domain_id)
        records = list(filter(lambda item: item["host"] == "standalone" and item["type"] == "A", domainRecords))
        if (len(records) == 0):
            error("No A Record present")
            return None
        else:
            return records[0]['id']
    def updateIpv4Record(self, record_id, ip):
        record = { "host": ddns_prefix, "ttl": 3600, "type": "A", "data": ip }
        try:
            self.client.modify_record(self.domain_id, record_id, record)
            return True
        except Exception as e:
            error(e)
            return False
    def setIpv4Record(self, ip):
        record = { "host": ddns_prefix, "ttl": 3600, "type": "A", "data": ip }
        try:
            self.client.create_record(self.domain_id, record)
            return True
        except Exception as e:
            error(e)
            return False

    #IPv6
    def getIpv6RecordId(self):
        domainRecords = self.client.get_records(self.domain_id)
        records = list(filter(lambda item: item["host"] == "standalone" and item["type"] == "AAAA", domainRecords))
        if (len(records) == 0):
            warn("No AAAA Record present")
            return None
        else:
            return records[0]['id']
    def updateIpv6Record(self, record_id, ip):
        record = { "host": ddns_prefix, "ttl": 3600, "type": "AAAA", "data": ip }
        try:
            self.client.modify_record(self.domain_id, record_id, record)
            return True
        except Exception as e:
            error(e)
            return False
    def setIpv6Record(self, ip):
        record = { "host": ddns_prefix, "ttl": 3600, "type": "AAAA", "data": ip }
        try:
            info("Creating AAAA Record with {}".format(record))
            self.client.create_record(self.domain_id, record)
            return True
        except Exception as e:
            warn(e)
            return False 

    def updateDestination(self, ip, gen):
        result = False
        if (gen == 4):
            record_id = self.getIpv4RecordId()
            if (record_id == None):
                info("Requesting Record A Creation")
                result = self.setIpv4Record(ip)
            else:
                info("Requesting Record A Update")
                result = self.updateIpv4Record(record_id, ip)

            if (result == True):
                success("Updated domain {} with A Record and IP {}".format(ddns, ip))
            else:
                error("Failed to update domain {} with A Record IP {}".format(ddns, ip))

        elif (gen == 6):
            record_id = self.getIpv6RecordId()
            if (record_id == None):
                info("Requesting Record AAAA Creation")
                result = self.setIpv6Record(ip)
            else:
                info("Requesting Record AAAA Update")
                result = self.updateIpv6Record(record_id, ip)

            if (result == True):
                success("Updated domain {} with AAAA Record and IP {}".format(ddns, ip))
            else:
                warn("Failed to update domain {} with AAAA Record IP {}".format(ddns, ip))
        return result
domainRegistery = registery()

def updateDns(addr, gen):
    global ipv4_lock
    global ipv6_lock
    info("Updating DNS record with IP: {}".format(addr))
    if (ipv4_lock is not None and time.time() < ipv4_lock and gen == 4):
        warn("DDNS aborted due to timelock in effect for IPv4. {}s Remaining".format((ipv4_lock - time.time())))
        return
    elif (ipv6_lock is not None and time.time() < ipv6_lock and gen == 6):
        warn("DDNS aborted due to timelock in effect for IPv6. {}s Remaining".format((ipv4_lock - time.time())))
        return

    # Calls class to update
    success = domainRegistery.updateDestination(addr, gen)
    if (success and gen == 4):
        ipv4_lock = time.time() + datetime.timedelta(hours=2).seconds
        warn("Setting time lock on IPv4 {} on Domain {}".format(addr, ddns))
        info("DDNS changes will be available after 2h")
        time.sleep(30)
        lookup4()
    elif (success and gen == 6):
        ipv6_lock = time.time() + datetime.timedelta(hours=2).seconds
        warn("Setting time lock on IPv6 {} on Domain {}".format(addr, ddns))
        info("DDNS changes will be available after 2h")
        time.sleep(30)
        lookup6()


def updateIpv4():
    ip = ipv4()[0]
    updateDns(ip, 4)

def updateIpv6():
    ip = ipv6()[0]
    sanitizedIp = str(ip).split("%", 1)[0]
    updateDns(sanitizedIp, 6)



def getResolver():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ '151.249.124.1', '2a01:5b40:ac1::1' ] # Using ns1.hyp.net from domeneshop
    return resolver
def lookup4():
    global dns_ipv4
    try:
        result = getResolver().resolve(ddns, 'A')
        sources = [s.to_text() for s in result]
        if (len(sources) > 0):
            dns_ipv4 = sources[0]
            info("Dns IP: {}".format(dns_ipv4))
    except:
        error("Could not find Domain {} with a IPv4 address".format(ddns))
        dns_ipv4 = None


def lookup6():
    global dns_ipv6
    try:
        result = getResolver().resolve(ddns, 'AAAA')
        sources = [s.to_text() for s in result]
        if (len(sources) > 0):
            dns_ipv6 = sources[0]
            info("Dns IP: {}".format(dns_ipv6))
    except:
        error("Could not find Domain {} with a IPv6 address".format(ddns))
        dns_ipv6 = None



def netInterface():
    net = netifaces.ifaddresses(interface)
    return net

def ipv4():
    iface4 = netInterface()[netifaces.AF_INET]
    ipv4s = [ip['addr'] for ip in iface4]
    return ipv4s

def ipv6():
    iface6 = netInterface()[netifaces.AF_INET6]
    ipv6s = [str(ip['addr']).split("%", 1)[0] for ip in iface6]
    return ipv6s

def hasIpv4Assigned():
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr

def isIpv6LinkLocal():
    addr = ipv6()[0]
    if (addr.split(":")[0] == "fe80"):
        return True
    else:
        return False

    
while True:
    lookup4()
    lookup6()


    if (hasIpv4Assigned() == False):
        error("No IPv4 address found on interface {}".format(interface))
        info("Attempting to request new ip with >> dhclient on interface {}".format(interface))
        dh = subprocess.Popen(["dhclient", "-i", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = dh.communicate()

        if (err != None or len(err.decode("utf-8")) > 0):
            error(err)
        if (out == None or len(out.decode("utf-8")) >= 0):
            info(out)
        time.sleep(60)
    
    cache_ipv4 = ipv4()

    if (isIpv6LinkLocal() == False):
        cache_ipv6 = ipv6()

        if (dns_ipv6 == None or dns_ipv6 not in cache_ipv6) == True:
            if (dns_ipv6 == None):
                warn("IPv6 (AAAA Record) not present on Domain {}".format(ddns))
            else:
                warn("{} not found in adapter ip {}".format(dns_ipv6, ipv6()))
            updateIpv6()
        elif (dns_ipv6 in cache_ipv6):
            info("Domain AAAA Record looks good")


    if (dns_ipv4 == None or dns_ipv4 not in cache_ipv4) == True:
        if (dns_ipv4 == None):
            error("IPv4 (A Record) not present on Domain {}".format(ddns))
        else:
            error("{} not found in adapter ip {}".format(dns_ipv4, ipv4()))
        updateIpv4()
    elif (dns_ipv4 in cache_ipv4):
        info("Domain A Record looks good")



    time.sleep(600)
    