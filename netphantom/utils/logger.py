import logging
import json
import time
from datetime import datetime
from typing import Any, Dict

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if available
        if hasattr(record, "extra"):
            log_data.update(record.extra) # type: ignore
            
        return json.dumps(log_data)

def setup_logger(name: str = "netphantom", level: int = logging.INFO) -> logging.Logger:
    """Sets up a logger with JSON formatting."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        
    return logger

logger = setup_logger()
base_logger = logger
