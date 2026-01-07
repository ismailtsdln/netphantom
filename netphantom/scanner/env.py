import socket
import netifaces
from typing import Dict, Any
from netphantom.utils.logger import logger

class EnvScanner:
    """Detects network environment details before starting poisoning."""
    
    @staticmethod
    def check_ipv6_availability(interface: str) -> bool:
        addrs = netifaces.ifaddresses(interface)
        return netifaces.AF_INET6 in addrs

    @staticmethod
    def get_interface_ip(interface: str) -> str:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
        raise ValueError(f"No IPv4 address found on interface {interface}")

    @staticmethod
    async def scan_smb_signing(target_ip: str) -> bool:
        """
        Check if SMB signing is required on target.
        This is a simplified check; in production, this would use Scapy or 
        a specialized lib to check the SMB negotiation flags.
        """
        # Placeholder for actual SMB negotiation check
        logger.info(f"Scanning SMB signing for {target_ip} (Simplified Check)")
        return False # Defaulting to false for this demo logic

    @classmethod
    async def gather_intel(cls, interface: str) -> Dict[str, Any]:
        intel = {
            "interface": interface,
            "ipv6_available": cls.check_ipv6_availability(interface),
            "local_ip": cls.get_interface_ip(interface),
        }
        logger.info(f"Gathered environment intel: {intel}")
        return intel

