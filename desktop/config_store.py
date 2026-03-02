"""Persistent configuration stored in ~/.automaite/"""

import json
import secrets
from pathlib import Path

AUTOMAITE_DIR = Path.home() / ".automaite"
CONFIG_FILE = AUTOMAITE_DIR / "config.json"

_DEFAULTS = {
    "relay_url": "https://term.automaite.ca",
    "agent_token": "",
}


def _ensure_dir():
    AUTOMAITE_DIR.mkdir(parents=True, exist_ok=True)


def load() -> dict:
    """Load config from disk, creating defaults if needed."""
    _ensure_dir()
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            cfg = {}
    else:
        cfg = {}

    changed = False
    for k, v in _DEFAULTS.items():
        if k not in cfg:
            cfg[k] = v
            changed = True

    if changed:
        save(cfg)

    return cfg


def save(cfg: dict):
    """Persist config to disk."""
    _ensure_dir()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get(key: str, default=None):
    cfg = load()
    return cfg.get(key, default)


def set(key: str, value):
    cfg = load()
    cfg[key] = value
    save(cfg)
