import ipaddress
import re
from domeneshop import Client
from .objects import RecordNotFoundException, NotAValidIpException, Auth
import tldextract
import logging

logging.basicConfig(level=logging.INFO)


class Registry:
    __client: Client | None = None
    __domain: str | None = None
    __domain_id: int | None = None
    fqdn: str | None = None

    def __init__(self, fqdn: str, auth: Auth) -> None:
        self.fqdn = fqdn
        self.__client = Client(token=auth.token, secret=auth.secret)
        extracted = tldextract.extract(self.fqdn)
        self.__domain = f"{extracted.domain}.{extracted.suffix}"
        self.__domain_id = self.__resolveDomainId()

    def __resolveDomainId(self) -> int:
        domains = self.__client.get_domains()
        if (len(domains) == 0):
            logging.error(f"No dmains found using domain: {self.__domain} obtained from FQDN: {self.fqdn}")
            return None
        record = next(filter(lambda entry: entry['domain'] == self.__domain, domains))
        if record is not None:
            return record['id']
        else:
            return None  
    
    def __find_recordId(self, fqdn: str, type: str = "A") -> int | None:
        """
        Looks up the records from the parent domain __domain and compares it to the fqdn (fully qualified domain name)

        :return: record id if the record exists
        """
        path = self.get_path(fqdn=fqdn)
        if (path is None):
            return None
        
        records = self.__client.get_records(self.__domain_id)
        record = next(filter(lambda record: record["host"] == path and record["type"] == type, records))
        if record is not None:
            return record["id"]
        else:
            return None

    def get_path(self, fqdn: str) -> str | None:
        path: str | None = None

        if (fqdn == self.__domain):
            path = "@"
        else:
            topDomainMatch = rf'^([a-zA-Z0-9-]+\.)*{re.escape(self.__domain)}$'
            if (re.match(topDomainMatch, fqdn)):
                prefixPattern = rf'\.?{re.escape(self.__domain)}$'
                path = re.sub(prefixPattern, '', fqdn)
            else:
                return None
        return path

    def update_record(self, fqdn: str, record: dict) -> bool:
        """

        """
        type = record["type"]
        recordId = self.__find_recordId(fqdn=fqdn, type=type)
        if (recordId is None):
            raise RecordNotFoundException(f"Could not find record or id of record based on the FQDN {fqdn} with type {type}.\n\tPlease ensure that the record already exists at the domain registar")
        try:
            self.__client.modify_record(self.__domain_id, recordId, record)
            return True
        except:
            return False
        
    def build_record(self, fqdn: str, ip: str) -> dict | None:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return self.__record4(fqdn=fqdn, ip=ip)
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return self.__record6(fqdn=fqdn, ip=ip)
        except ValueError:
            raise NotAValidIpException(f"The ip provided: {ip}")
        pass

    
    def __record4(self, fqdn: str, ip: str) -> dict:
        return { "host": self.get_path(fqdn=fqdn), "ttl": 3600, "type": "A", "data": ip }

    def __record6(self, fqdn: str, ip: str) -> dict:
        return { "host": self.get_path(fqdn=fqdn), "ttl": 3600, "type": "AAAA", "data": ip }

