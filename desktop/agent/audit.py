import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Default to ~/.automaite/audit.log when bundled with desktop app
_default_path = os.path.join(Path.home(), ".automaite", "audit.log")
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", _default_path)

# Ensure directory exists
os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

_handler = RotatingFileHandler(
    AUDIT_LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5
)
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit_logger.addHandler(_handler)


def log_event(event_type: str, **kwargs):
    parts = [f"event={event_type}"]
    for k, v in kwargs.items():
        parts.append(f"{k}={v!r}")
    audit_logger.info(" ".join(parts))
