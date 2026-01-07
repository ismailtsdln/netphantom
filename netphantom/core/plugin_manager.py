import importlib
import inspect
import pkgutil
from typing import Dict, List, Type, cast, Any
from netphantom.core.interfaces import BasePlugin, ProtocolPlugin, AuthHandler
from netphantom.utils.logger import logger

class PluginManager:
    """Discovers and manages NetPhantom plugins."""
    
    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self.protocols: Dict[str, ProtocolPlugin] = {}
        self.handlers: Dict[str, AuthHandler] = {}

    def _discover_in_package(self, package_path: str, base_class: Type) -> List[Type]:
        discovered = []
        try:
            package = importlib.import_module(package_path)
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__):
                full_name = f"{package_path}.{name}"
                module = importlib.import_module(full_name)
                for _, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, base_class) and obj is not base_class:
                        discovered.append(obj)
        except Exception as e:
            logger.error(f"Failed to discover plugins in {package_path}: {e}")
        return discovered

    async def load_plugins(self, config: Dict[str, Any] = None):
        """Discovers and initializes plugins."""
        config = config or {}
        
        # Load Protocols
        proto_classes = self._discover_in_package("netphantom.plugins.protocols", ProtocolPlugin)
        for cls in proto_classes:
            try:
                instance = cast(ProtocolPlugin, cls())
                await instance.setup(config.get(instance.name, {}))
                self.protocols[instance.name] = instance
                self.plugins[instance.name] = instance
                logger.info(f"Loaded protocol plugin: {instance.name}")
            except Exception as e:
                logger.error(f"Failed to load protocol {cls.__name__}: {e}")

        # Load Handlers
        handler_classes = self._discover_in_package("netphantom.plugins.handlers", AuthHandler)
        for cls in handler_classes:
            try:
                instance = cast(AuthHandler, cls())
                await instance.setup(config.get(instance.name, {}))
                self.handlers[instance.name] = instance
                self.plugins[instance.name] = instance
                logger.info(f"Loaded auth handler: {instance.name}")
            except Exception as e:
                logger.error(f"Failed to load handler {cls.__name__}: {e}")

    async def start_all(self):
        logger.info(f"Starting {len(self.plugins)} plugins...")
        await asyncio.gather(*[plugin.start() for plugin in self.plugins.values()])

    async def stop_all(self):
        logger.info(f"Stopping {len(self.plugins)} plugins...")
        await asyncio.gather(*[plugin.stop() for plugin in self.plugins.values()])
