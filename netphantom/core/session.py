import json
import time
from typing import Dict, List, Any
from pydantic import BaseModel
from netphantom.utils.logger import logger

class Credential(BaseModel):
    source_ip: str
    protocol: str
    handler: str
    data: Dict[str, Any]
    timestamp: float

class SessionManager:
    """Manages captured credentials and session state."""
    
    def __init__(self, save_path: str = "intercepted_sessions.json"):
        self.save_path = save_path
        self.credentials: List[Credential] = []

    async def add_intercept(self, source_ip: str, protocol: str, handler: str, data: Dict[str, Any]):
        cred = Credential(
            source_ip=source_ip,
            protocol=protocol,
            handler=handler,
            data=data,
            timestamp=time.time()
        )
        self.credentials.append(cred)
        logger.info(f"New credential session registered from {source_ip} via {protocol}/{handler}")
        await self._async_save()

    async def _async_save(self):
        """Asynchronously save sessions to disk."""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._save_sync)
        except Exception as e:
            logger.error(f"Failed to trigger async save: {e}")

    def _save_sync(self):
        try:
            with open(self.save_path, "w") as f:
                json.dump([c.model_dump() for c in self.credentials], f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")

    def get_summary(self) -> str:
        return f"Total captured sessions: {len(self.credentials)}"

