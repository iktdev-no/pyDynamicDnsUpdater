import logging
import random
from threading import Thread
import threading
import traceback
import queue
from typing import List
import os, sys, time, errno

from .Registry import Registry
from .Resolve import Resolve
from .objects import IpData, Auth, DDNSEntry
from .NetworkAdapter import NetworkAdapter

logging.basicConfig(level=logging.INFO)

class NetworkHookHandler:
    """
    """
    __mainThread = threading.current_thread
    
    # Create a queue to hold messages received from the pipe
    message_queue = queue.Queue()

    # Create a mutex to coordinate access to the queue
    message_mutex = threading.Lock()
    
    # Create a condition variable to notify waiting threads of new messages
    message_cond = threading.Condition(message_mutex)
    
    
    hookThreads: List[Thread] = []
    pipe_path = "/tmp/ddns-hook"
    
    stopFlag = threading.Event()
    
    ddnsEntries: List[DDNSEntry] = []
    auth: Auth

    nics: List[str] = []
    resolve = Resolve()

        
    def __init__(self, auth: Auth, config: List[DDNSEntry]) -> None:
        self.auth = auth
        try:
            if not os.path.exists(self.pipe_path):
                os.mkfifo(path=self.pipe_path)
                os.chmod(self.pipe_path, mode=0o666)
        except OSError as oe:
            if oe.errno != errno.EEXIST:
                raise
        self.ddnsEntries = config
        self.nics = [entry.interface for entry in config]
                      
            
    def __openPipe(self) -> None:
        """_summary_"""
        logging.info(f"Opening pipe on {self.pipe_path}")
        with open(self.pipe_path, 'r') as fifo:
            while not self.stopFlag.is_set():
                content = fifo.read()
                lines = content.splitlines()
                if lines:
                    with self.message_mutex:
                        for line in lines:
                            message = line.strip()
                            if message and message in self.nics:
                                logging.info(f"DDNSHook Received message from hook: {message}")
                                self.message_queue.put(message)
                            elif message == "stop":
                                logging.info(f"DDNSHook Received fifo stop: {message}")
                                self.stopFlag.set()
                            else:
                                if len(message) > 0:
                                    logging.error(f"DDNSHook is ignoring: {message} as it expects one of your predefined values or stop")
                        self.message_cond.notify_all()
                    with open(self.pipe_path, "w") as fifo_truncate:
                        logging.info("Truncating message cache")
                        fifo_truncate.write('')
                else:
                    time.sleep(1)
        logging.info(f"Pipe is closed!")


            
                
    def start(self) -> None:
        """Starts Thread that opens pipe and watches it for changes
        Returns:
            Thread: DDNSHookThread that has been started
        """
        _pthread = threading.Thread(target=self.__openPipe)
        self.hookThreads.append(_pthread)
        _pthread.start()
        for nic in self.nics:
            _hthread = threading.Thread(target=self.__onThreadStart, kwargs={'targetName': nic})
            self.hookThreads.append(_hthread)
            _hthread.start()
    
        
    def dryrun(self) -> None:
        """Runs all operations on defined interfaces
        """
        logging.info("DDNSHook Dryrun started!\n")
        for nic in self.nics:
            self.__processMessage(nic)
        logging.info("\DDNSHook Dryrun completed!\n")
        
    def stop(self) -> None:
        """
        """
        logging.info("Setting stop flag for NetworkHookHandler")
        with open(self.pipe_path, 'w') as fifo:
            fifo.write('stop')
        logging.info("Setting stop flag")
        self.stopFlag.set()
        logging.info("Threads stopped..")            
        
    def __onThreadStart(self, targetName: str) -> None:
        """
        """
        if self.__mainThread == threading.current_thread():
            logging.error("DDNSHook has not been started in a separete thread!")
            raise Exception("DDNSHook is started in main thread!")
        logging.info(f"DDNSHook Thread Started for {targetName}")
        
        while not self.stopFlag.is_set():
            with self.message_mutex:
                if self.message_queue.empty():
                    timeout = random.uniform(1, 5)
                    self.message_cond.wait(timeout)
                    continue                   
                    
                message = self.message_queue.get()
                if message == targetName:
                    logging.info(f"DDNSHook Thread for {targetName} has received event")
                    self.__processMessage(message)
                else:
                    self.message_queue.put(message)
                 
    
    def __processMessage(self, nic: str) -> None:
        adapter: NetworkAdapter = NetworkAdapter(nic)
        ipdata = adapter.getIpData()
        if (ipdata.isValid()):
            self.__validateDnsRecordAgainstIpReceivedAndUpdate(nic, ipdata)
        else:
            logging.info(f"Adding puller on {nic}")
            self.__puller_add(nic)
                
    def __validateDnsRecordAgainstIpReceivedAndUpdate(self, nic: str, ipdata: IpData) -> None:
        ddnsEntry = next(filter(lambda entry: entry.interface == nic, self.ddnsEntries))
        if (ddnsEntry.ipv4 == True):
            invalidPointers = self.__find_invalid_pointer4(ipdata.ip, ddnsEntry.domains)
            for invalidPointer in invalidPointers:
                registry = Registry(fqdn=invalidPointer, auth=self.auth)
                record = registry.build_record(fqdn=invalidPointer, ip=ipdata.ip)
                logging.info(f"Preparing record for FQDN {invalidPointer}\n\t -> {record}")
                registry.update_record(invalidPointer, record)
        if (ddnsEntry.ipv6 == True):
            invalidPointers = self.__find_invalid_pointer6(ipdata.ipv6, ddnsEntry.domains)
            for invalidPointer in invalidPointers:
                registry = Registry(fqdn=invalidPointer, auth=self.auth)
                record = registry.build_record(fqdn=invalidPointer, ip=ipdata.ipv6)
                logging.info(f"Preparing record for FQDN {invalidPointer}\n\t -> {record}")
                registry.update_record(invalidPointer, record)

    def __find_invalid_pointer4(self, ip: str, domains: List[str]) -> List[str]:
        invalids: List[str] = []
        for domain in domains:
            result = self.resolve.lookup4(domain)
            if (result.ip != ip):
                invalids.append(domain)
        return invalids
    
    def __find_invalid_pointer6(self, ip: str, domains: List[str]) -> List[str]:
        invalids: List[str] = []
        for domain in domains:
            result = self.resolve.lookup6(domain)
            if (result.ip != ip):
                invalids.append(domain)
        return invalids
       
            
    nicsPullerThreads: List[Thread] = []

    def __puller_add(self, nic: str) -> None:
        """Pulls on network adapter in seperate thread
        """
        waitTime: int = 60
        if len(list(filter(lambda x: x.name == nic, self.nicsPullerThreads))) != 0:
            logging.info(f"Found existing thread for {nic} skipping..")
            return
        thread = Thread(
            name=nic,
            target=self.__puller_thread,
            args=(nic,waitTime)
        )
        self.nicsPullerThreads.append(thread)
        thread.start()
        
    def __puller_remove(self, name: str) -> None:
        """Removes puller
        """
        try:
            if (len(self.nicsPullerThreads) > 0):
                targetThread = next(filter(lambda x: x.name == name, self.nicsPullerThreads))
                self.nicsPullerThreads.remove(targetThread)
        except Exception as e:
            logging.log("Exception occured when attempting to remove a thread from pullers")
            logging.exception(e)
    
    def __puller_thread(self, nic: str, waitTime: int = 60) -> None:
        """Thread for pulling on adapter
        """
        logging.info(f"Starting pulling on {nic}")
        
        isInInvalidState: bool = True
        while isInInvalidState or not self.stopFlag.is_set():
            time.sleep(waitTime)
            ipdata = NetworkAdapter(nic).getIpData()
            isInInvalidState = not ipdata.isValid()
            print(ipdata)
            if (isInInvalidState == False):
                self.__puller_remove(nic)
                self.__routingTable_modify(ipdata)
            else:
                logging.info(f"Pulling on {nic} in {waitTime}s")
        logging.info(f"Pulling on {nic} has ended")
        
