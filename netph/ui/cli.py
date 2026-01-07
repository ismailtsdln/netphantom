import sys
import time
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from netph.core.engine import PoisoningEngine
from netph.capture.sniffer import AuthSniffer
from netph.utils.logger import logger

console = Console()

def display_banner():
    banner = """
    [bold cyan]
     _   _      _   ____  _                 _                 
    | \ | | ___| |_|  _ \| |__   __ _ _ __ | |_ ___  _ __ ___  
    |  \| |/ _ \ __| |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \ 
    | |\  |  __/ |_|  __/| | | | (_| | | | | || (_) | | | | | |
    |_| \_|\___|\__|_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|
                                                                
    [bold yellow]Network Phantom Poisoning & Authentication Capture Tool[/bold yellow]
    """
    console.print(Panel(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="NetPhantom - Network Poisoning Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-s", "--spoof-ip", required=True, help="IP address to spoof")
    parser.add_argument("-p", "--protocols", nargs="+", default=["llmnr", "nbt_ns", "mdns"], help="Protocols to poison (default: all)")
    
    args = parser.parse_args()

    display_banner()
    
    engine = PoisoningEngine(args.interface, args.spoof_ip, args.protocols)
    sniffer = AuthSniffer(args.interface)

    try:
        engine.start()
        sniffer.start()
        
        console.print(f"\n[bold green][+][/bold green] NetPhantom is running on [bold]{args.interface}[/bold]")
        console.print("[bold yellow][!][/bold yellow] Press Ctrl+C to stop...\n")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/bold red] Stopping NetPhantom...")
        engine.stop()
        sniffer.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
