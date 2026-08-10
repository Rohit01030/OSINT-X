"""
Central logging configuration.

Logs go to the console (for `docker compose logs`) and to a rotating
logs/app.log file (for anything that needs to be inspected after the
container has stopped, e.g. debugging a crashed lookup job in a later phase).
"""
import logging
import os
from logging.handlers import RotatingFileHandler

from core.config import settings


def setup_logging() -> None:
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, "app.log"),
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Quiet down noisy access logs from uvicorn so app logs stay readable
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
