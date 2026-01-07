import os
import json
import pytest
from netph.utils.config import ConfigManager

def test_default_config():
    config = ConfigManager("test_config.json")
    assert config.get("poisoning")["llmnr"] is True
    assert config.get("interface") == "eth0"
    if os.path.exists("test_config.json"):
        os.remove("test_config.json")

def test_load_config():
    test_data = {"interface": "wlan0"}
    with open("test_config.json", "w") as f:
        json.dump(test_data, f)
    
    config = ConfigManager("test_config.json")
    assert config.get("interface") == "wlan0"
    
    if os.path.exists("test_config.json"):
        os.remove("test_config.json")

