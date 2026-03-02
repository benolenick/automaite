"""Playbook storage — JSON file at ~/.automaite/playbooks.json"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

AUTOMAITE_DIR = Path.home() / ".automaite"
PLAYBOOKS_FILE = AUTOMAITE_DIR / "playbooks.json"


def _load_playbooks() -> list[dict]:
    if not PLAYBOOKS_FILE.exists():
        return []
    try:
        data = json.loads(PLAYBOOKS_FILE.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_playbooks(playbooks: list[dict]):
    AUTOMAITE_DIR.mkdir(parents=True, exist_ok=True)
    PLAYBOOKS_FILE.write_text(json.dumps(playbooks, indent=2))


def list_playbooks() -> list[dict]:
    return _load_playbooks()


def get_playbook(playbook_id: str) -> dict | None:
    for pb in _load_playbooks():
        if pb["id"] == playbook_id:
            return pb
    return None


def create_playbook(
    name: str,
    agent_type: str,
    agent_config: dict,
    instructions: str = "",
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    pb = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "agent_type": agent_type,
        "agent_config": agent_config,
        "instructions": instructions,
        "created_at": now,
        "updated_at": now,
    }
    playbooks = _load_playbooks()
    playbooks.append(pb)
    _save_playbooks(playbooks)
    return pb


def update_playbook(playbook_id: str, **fields) -> dict | None:
    playbooks = _load_playbooks()
    for pb in playbooks:
        if pb["id"] == playbook_id:
            for k, v in fields.items():
                if v is not None:
                    pb[k] = v
            pb["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_playbooks(playbooks)
            return pb
    return None


def delete_playbook(playbook_id: str) -> bool:
    playbooks = _load_playbooks()
    original_len = len(playbooks)
    playbooks = [pb for pb in playbooks if pb["id"] != playbook_id]
    if len(playbooks) == original_len:
        return False
    _save_playbooks(playbooks)
    return True
