from scapy.all import *
from netph.utils.logger import logger
import base64
import struct
import threading

class AuthSniffer:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self._thread = None

    def _handle_packet(self, packet: Packet):
        # HTTP NTLM Capture
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if "Authorization: NTLM" in payload:
                self._parse_http_ntlm(payload, packet)
            elif "WWW-Authenticate: NTLM" in payload:
                self._parse_http_ntlm_auth(payload, packet)

    def _parse_http_ntlm(self, payload: str, packet: Packet):
        # Extract NTLM blob from Authorization header
        for line in payload.splitlines():
            if line.startswith("Authorization: NTLM"):
                ntlm_blob = line.split(" ")[2]
                logger.info(f"[Capture] Received NTLM Blob from {packet[IP].src}")
                # Further parsing would happen here (Type 1 or Type 3)
                # For now, just logging the event
                break

    def _parse_http_ntlm_auth(self, payload: str, packet: Packet):
        for line in payload.splitlines():
            if line.startswith("WWW-Authenticate: NTLM"):
                ntlm_blob = line.split(" ")[2]
                logger.info(f"[Capture] Server challenge from {packet[IP].src}")
                break

    def start(self):
        self.running = True
        logger.info(f"[Capture] Starting sniffer on {self.interface}...")
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

    def _run(self):
        sniff(iface=self.interface, filter="tcp port 80 or tcp port 445", prn=self._handle_packet, store=0, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join()
        logger.info("[Capture] Stopped sniffer.")
 PelicanAuthSniffer = AuthSniffer # Alias if needed
