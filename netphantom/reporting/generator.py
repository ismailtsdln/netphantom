import json
from datetime import datetime
from typing import List, Dict, Any
from netphantom.core.session import Credential

class ReportGenerator:
    """Generates pentest-ready reports from captured session data."""
    
    MITRE_MAPPING = {
        "llmnr": "T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)",
        "nbt_ns": "T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)",
        "mdns": "T1557 (Adversary-in-the-Middle)",
        "http_auth": "T1557 (Adversary-in-the-Middle)"
    }

    @classmethod
    def generate_markdown(cls, credentials: List[Credential], output_path: str):
        report = [
            "# NetPhantom - Security Interception Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\n## Executive Summary",
            f"Total unique interceptions identified: {len(credentials)}",
            "\n## Interception Details",
            "| Source IP | Protocol | Handler | MITRE ATT&CK | Timestamp |",
            "|-----------|----------|---------|--------------|-----------|"
        ]

        for cred in credentials:
            mitre = cls.MITRE_MAPPING.get(cred.protocol, "N/A")
            ts = datetime.fromtimestamp(cred.timestamp).strftime('%H:%M:%S')
            report.append(f"| {cred.source_ip} | {cred.protocol} | {cred.handler} | {mitre} | {ts} |")

        report.append("\n## Security Impact")
        report.append("Successful poisoning of name resolution protocols allows an attacker to divert traffic to malicious endpoints, potentially capturing sensitive authentication material (hashes) for further relay or cracking.")
        
        with open(output_path, "w") as f:
            f.write("\n".join(report))

