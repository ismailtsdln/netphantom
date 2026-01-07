import asyncio
import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from netphantom.core.engine import CoreEngine
from netphantom.core.config import load_profile
from netphantom.scanner.env import EnvScanner
from netphantom.utils.logger import logger

console = Console()

def display_banner():
    banner = """
    [bold red]
     ███╗   ██╗███████╗████████╗██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
     ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
     ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
     ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
     ██║ ╚████║███████╗   ██║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
     ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
    [/bold red]
    [bold white]Modular Offensive Network Credential Interception Framework[/bold white]
    """
    console.print(Panel(banner, border_style="red", padding=(1, 2)))

async def main():
    parser = argparse.ArgumentParser(description="NetPhantom Framework")
    parser.add_argument("--profile", required=True, help="Path to the YAML profile")
    parser.add_argument("--dry-run", action="store_true", help="Execute in dry-run mode (no packets)")
    
    args = parser.parse_args()

    display_banner()
    
    try:
        # 1. Load Profile
        config = load_profile(args.profile)
        if args.dry_run:
            config.poisoning.dry_run = True
            console.print("[bold yellow]![/] Running in DRY-RUN mode.")

        # 2. Environment Intel
        intel = await EnvScanner.gather_intel(config.poisoning.interface)
        console.print(f"[bold green]+[/] Interface: {intel['interface']} | IP: {intel['local_ip']} | IPv6: {intel['ipv6_available']}")

        # 3. Initialize & Start Engine
        engine = CoreEngine(config.dict())
        await engine.start()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Critical engine failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
