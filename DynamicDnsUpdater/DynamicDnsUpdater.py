import logging
from io import TextIOWrapper
import json
import random
import signal
from threading import Thread

from DynamicDnsUpdater.IpDnsPoller import IpDnsPoller
from .version import __version__

from .objects import DDNSEntry, Auth
from typing import List

from .NetworkHookHandler import NetworkHookHandler
import os, sys, time, re, errno
import netifaces # type: ignore


class DynamicDnsUpdater:

    networkHookHandler: NetworkHookHandler
    ipDnsPoller: IpDnsPoller

    def __faces(self) -> str:
        faces: List[str] = [
            "( °ヮ° )",
            "(｡·  v  ·｡)",
            "( ô ‸ ō )",
            "( • - • )",
            "ᯣ_ᯣ",
            "(𖦹﹏𖦹;)",
            "◑—◑",
            "⫍‍⌕‍⫎",
            "(⊙ _ ⊙ )"
        ]
        return random.choice(faces)
        
    
    def __init__(self, reference: str = "reference.json", auth: str = "auth.json") -> None:
        sys.stdout.write(f"{self.__faces()}\n")
        logging.info(f"Version: {__version__}")
        logging.info("Loading up Dynamic Dns Updater")
        logging.info("Reading configuration")
        auth: dict = json.load(open(auth))
        reference: dict = json.load(open(reference))

        authData = self.parse_auth(auth)
        ddnsEntries = self.parse_reference(reference)

        self.networkHookHandler = NetworkHookHandler(auth=authData, config=ddnsEntries)
        self.ipDnsPoller = IpDnsPoller(auth=authData, ddnsEntries=ddnsEntries)

        signal.signal(signal.SIGINT, self.__stop)


    def start(self) -> None:
        self.setup()
        self.networkHookHandler.start()
        self.ipDnsPoller.start()
    
    def stop(self) -> None:
        self.ipDnsPoller.stop()
        self.networkHookHandler.stop()
        logging.info("Stopped DRUHook and removed created Routing Table entries")

    def __stop(self, sig, _):
        logging.info(f"Signal {sig} received. Cleaning up and exiting gracefully...")
        self.stop()
        exit(0)


    def setup(self) -> None:
        """_summary_
        """
        availableNetworkAdapters = netifaces.interfaces()
        logging.info("Running pre-check")
        if set(self.nics).issubset(set(availableNetworkAdapters)):
            logging.info("Configured interfaces are present!")
        else:
            logging.error("Configured interfaces are not present!")
            missingNetworkAdapters = [verdi for verdi in self.nics if verdi not in availableNetworkAdapters]
            for missing in missingNetworkAdapters:
                logging.error(f"\t{missing}")
            logging.warn("Verify that your configuration corresponds to your available network adapters")
            exit(1)

    def parse_reference(self, reference: dict) -> List[DDNSEntry]:
        entries: List[DDNSEntry] = []
        for key, value in reference.items():
            entries.append(
                DDNSEntry(
                    interface=key,
                    ipv4=value["ipv4"],
                    ipv6=value["ipv6"],
                    domains=value["domains"]
                )
            )
        return entries
    
    def parse_auth(self, auth: dict) -> Auth:
        return Auth(
            auth["token"],
            auth["secret"]
        )