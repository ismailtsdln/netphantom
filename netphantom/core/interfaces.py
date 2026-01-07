from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pydantic import BaseModel

class Event(BaseModel):
    """Base event model for the framework."""
    type: str
    source: str
    data: Dict[str, Any]
    timestamp: float

class BasePlugin(ABC):
    """Base interface for all NetPhantom plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @abstractmethod
    async def setup(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with its configuration."""
        pass

    @abstractmethod
    async def start(self) -> None:
        """Start the plugin's execution."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the plugin gracefully."""
        pass

class ProtocolPlugin(BasePlugin):
    """Specific interface for network poisoning protocols."""
    pass

class AuthHandler(BasePlugin):
    """Specific interface for authentication capture handlers."""
    pass
