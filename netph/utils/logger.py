import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_logger(name: str = "netphantom", level: int = logging.INFO) -> logging.Logger:
    """Sets up a logger with RichHandler."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)]
    )
    
    logger = logging.getLogger(name)
    return logger


