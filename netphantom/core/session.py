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

    def add_intercept(self, source_ip: str, protocol: str, handler: str, data: Dict[str, Any]):
        cred = Credential(
            source_ip=source_ip,
            protocol=protocol,
            handler=handler,
            data=data,
            timestamp=time.time()
        )
        self.credentials.append(cred)
        logger.info(f"New credential session registered from {source_ip} via {protocol}/{handler}")
        self._save()

    def _save(self):
        try:
            with open(self.save_path, "w") as f:
                json.dump([c.dict() for c in self.credentials], f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")

    def get_summary(self) -> str:
        return f"Total captured sessions: {len(self.credentials)}"
 PelicanSessionManager = SessionManager
