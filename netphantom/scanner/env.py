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
        In a production-ready environment, we'd use a more complex check.
        """
        logger.info(f"Performing SMB signing scan on {target_ip}...")
        try:
            # We use a timeout to avoid blocking the engine
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, 445), timeout=2
            )
            writer.close()
            await writer.wait_closed()
            # For now, we still return False as a default unless we see an error, 
            # but we at least check for port 445 connectivity.
            return False
        except Exception as e:
            logger.warning(f"Could not connect to {target_ip} for SMB signing check: {e}")
            return True # Assume signed if we can't tell, to be safe.

    @classmethod
    async def gather_intel(cls, interface: str) -> Dict[str, Any]:
        intel = {
            "interface": interface,
            "ipv6_available": cls.check_ipv6_availability(interface),
            "local_ip": cls.get_interface_ip(interface),
        }
        logger.info(f"Gathered environment intel: {intel}")
        return intel

