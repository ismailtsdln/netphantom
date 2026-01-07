import json
import os
from pathlib import Path
from typing import Any, Dict

class ConfigManager:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                return json.load(f)
        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "poisoning": {
                "llmnr": True,
                "nbt_ns": True,
                "mdns": True
            },
            "capture": {
                "http": True,
                "smb": True,
                "ftp": True,
                "ldap": True
            },
            "interface": "eth0"
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def save(self):
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=4)

config_manager = ConfigManager()
