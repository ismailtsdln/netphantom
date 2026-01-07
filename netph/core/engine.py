from netph.core.llmnr import LLMNRPoisoner
from netph.core.nbt_ns import NBNSPoisoner
from netph.core.mdns import MDNSPoisoner
from netph.utils.logger import logger

class PoisoningEngine:
    def __init__(self, interface: str, spoof_ip: str, protocols: list[str] = None):
        self.interface = interface
        self.spoof_ip = spoof_ip
        self.protocols = protocols or ["llmnr", "nbt_ns", "mdns"]
        self.poisoners = []
        
        self._setup_poisoners()

    def _setup_poisoners(self):
        if "llmnr" in self.protocols:
            self.poisoners.append(LLMNRPoisoner(self.interface, self.spoof_ip))
        if "nbt_ns" in self.protocols:
            self.poisoners.append(NBNSPoisoner(self.interface, self.spoof_ip))
        if "mdns" in self.protocols:
            self.poisoners.append(MDNSPoisoner(self.interface, self.spoof_ip))

    def start(self):
        logger.info(f"Starting poisoning engine on {self.interface} for protocols: {', '.join(self.protocols)}")
        for poisoner in self.poisoners:
            poisoner.start()

    def stop(self):
        logger.info("Stopping poisoning engine...")
        for poisoner in self.poisoners:
            poisoner.stop()

