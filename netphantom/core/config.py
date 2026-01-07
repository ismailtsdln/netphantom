from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field
from pathlib import Path
from netphantom.utils.logger import logger

class PoisoningConfig(BaseModel):
    enabled_protocols: List[str] = ["llmnr", "nbt_ns", "mdns"]
    spoof_ip: str
    interface: str
    dry_run: bool = False

class CaptureConfig(BaseModel):
    enabled_handlers: List[str] = ["http", "smb"]
    save_path: str = "captured_creds.json"

class SafetyConfig(BaseModel):
    allowed_ranges: List[str] = []
    kill_switch_path: Optional[str] = None

class AppConfig(BaseModel):
    poisoning: PoisoningConfig
    capture: CaptureConfig
    safety: SafetyConfig
    plugins: Dict[str, Dict[str, Any]] = {}

def load_profile(path: str) -> AppConfig:
    """Loads and validates a NetPhantom profile from YAML."""
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            return AppConfig(**data)
    except Exception as e:
        logger.error(f"Failed to load profile from {path}: {e}")
        raise
