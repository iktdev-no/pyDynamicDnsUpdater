import logging
import dns.resolver
from dns.resolver import Answer
from .objects import LookupResult

from typing import List
logging.basicConfig(level=logging.INFO)

class Resolve:
    __resolver = dns.resolver.Resolver()
    __primaryResolver4: List[str] = [
        "151.249.124.1"
    ]
    __primaryResolver6: List[str] = [
        "2a01:5b40:ac1::1"
    ]

    __alternativeResolver4: List[str] = []
    __alternativeResolver6: List[str] = []

    def setPrimaryResolver4(self, resolvers: List[str]) -> None:
        """
        Replaces the primary resolver which is used to verify that the record is correct and up to date at the domain registar
        """
        self.__primaryResolver4 = resolvers

    def setPrimaryResolver6(self, resolvers: List[str]) -> None:
        """
        Replaces the primary resolver which is used to verify that the record is correct and up to date at the domain registar
        """
        self.__primaryResolver6 = resolvers        
    
    def addPrimaryResolver4(self, resolvers: List[str]) -> None:
        """
        Adds a primary resolver which is used to verify that the record is correct and up to date at the domain registar
        """        
        self.__primaryResolver4.extend(resolvers)

    def addPrimaryResolver6(self, resolvers: List[str]) -> None:
        """
        Adds a primary resolver which is used to verify that the record is correct and up to date at the domain registar
        """                
        self.__primaryResolver6.extend(resolvers)

    def setAlternativeResolver4(self, resolvers: List[str]) -> None:
        """
        Sets alternative dns resolvers.
        Can be used to check how far the update has propegated
        """        
        self.__alternativeResolver4 = resolvers

    def setAlternativeResolver6(self, resolvers: List[str]) -> None:
        """
        Sets alternative dns resolvers.
        Can be used to check how far the update has propegated
        """          
        self.__alternativeResolver6 = resolvers           

    def __parse_lookup(self, domain: str, records: Answer) -> str | None:
        domainIp = None
        try:
            ips = [s.to_text() for s in records]
            if (len(ips) > 0):
                domainIp = ips[0] # Only use the first one, no round robin DNS supported # Should only be one record
        except:
            logging.error("Could not find Domain {} with a ip address".format(domain))
        return domainIp


    def lookup4(self, domain: str) -> LookupResult | None:
        self.__resolver.nameservers = self.__primaryResolver4
        try:
            records = self.__resolver.resolve(domain, 'A')
            return LookupResult(
                domain=domain,
                ip=self.__parse_lookup(domain, records)
            )
        except Exception as e:
            logging.exception(e)
            return None

    def lookup6(self, domain: str) -> LookupResult | None:
        self.__resolver.nameservers = self.__primaryResolver6
        try:
            records = self.__resolver.resolve(domain, 'AAAA')
            return LookupResult(
                domain=domain,
                ip=self.__parse_lookup(domain, records)
            )
        except Exception as e:
            logging.exception(e)
            return None