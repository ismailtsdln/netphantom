import asyncio
import signal
from typing import Any, Dict, Optional
from netphantom.core.plugin_manager import PluginManager
from netphantom.utils.logger import logger

class CoreEngine:
    """The central engine for NetPhantom framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.plugin_manager = PluginManager()
        self.running = False
        self._loop = asyncio.get_event_loop()

    def _setup_signals(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            self._loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))

    async def start(self):
        """Initializes and starts the framework."""
        logger.info("Initializing NetPhantom Core Engine...")
        self.running = True
        self._setup_signals()
        
        await self.plugin_manager.load_plugins(self.config.get("plugins", {}))
        await self.plugin_manager.start_all()
        
        logger.info("NetPhantom is now operational.")
        while self.running:
            await asyncio.sleep(1)

    async def stop(self):
        """Stops the framework gracefully."""
        if not self.running:
            return
        logger.info("Shutting down NetPhantom...")
        self.running = False
        await self.plugin_manager.stop_all()
        logger.info("Shutdown complete.")
        # self._loop.stop() # Be careful here if multiple tasks are running
