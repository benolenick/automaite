"""Per-user API key storage.

Stores user API keys encrypted on disk using Fernet (symmetric AES-CBC).
Key derivation uses HKDF-SHA256 from a dedicated KEYSTORE_SECRET env var.
Keys are stored in /data/user_keys.json (mapped as a Docker volume).
"""

import json
import logging
import os
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("relay.keystore")

# Derive Fernet key from KEYSTORE_SECRET using HKDF (proper KDF, not raw SHA-256)
_keystore_secret = os.environ.get("KEYSTORE_SECRET", "")
if not _keystore_secret:
    logger.warning("KEYSTORE_SECRET not set — keystore will not function")
    _fernet = None
else:
    _hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"automaite-keystore-v2",
        info=b"fernet-key",
    )
    _derived = _hkdf.derive(_keystore_secret.encode())
    _fernet_key = base64.urlsafe_b64encode(_derived)
    _fernet = Fernet(_fernet_key)

KEYS_FILE = Path("/data/user_keys.json")

# Supported key names
VALID_KEY_NAMES = {
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
}

# Map agent type -> required env var
AGENT_KEY_MAP = {
    "claude": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "codex": "OPENAI_API_KEY",
}


def _load_store() -> dict:
    if not KEYS_FILE.exists():
        return {}
    try:
        return json.loads(KEYS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_store(store: dict):
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEYS_FILE.write_text(json.dumps(store, indent=2))


def save_user_keys(email: str, keys: dict[str, str]):
    """Save encrypted API keys for a user. Only saves valid key names."""
    if _fernet is None:
        raise RuntimeError("Keystore not initialized — KEYSTORE_SECRET not set")
    store = _load_store()
    user_keys = store.get(email, {})

    for name, value in keys.items():
        if name not in VALID_KEY_NAMES:
            continue
        if value:  # Non-empty: encrypt and store
            encrypted = _fernet.encrypt(value.encode()).decode()
            user_keys[name] = encrypted
        elif name in user_keys:  # Empty string: delete
            del user_keys[name]

    store[email] = user_keys
    _save_store(store)
    logger.info("Saved %d keys for user %s", len(user_keys), email)


def get_user_keys(email: str) -> dict[str, str]:
    """Get decrypted API keys for a user. Returns {name: value}."""
    if _fernet is None:
        return {}
    store = _load_store()
    user_keys = store.get(email, {})
    result = {}
    for name, encrypted in user_keys.items():
        try:
            result[name] = _fernet.decrypt(encrypted.encode()).decode()
        except Exception:
            logger.warning("Failed to decrypt key %s for %s", name, email)
    return result


def get_user_key_names(email: str) -> list[str]:
    """Get list of stored key names (without values) for a user."""
    store = _load_store()
    return list(store.get(email, {}).keys())


def get_env_for_session(email: str, agent_type: str) -> dict[str, str]:
    """Get env vars to inject for a session based on agent type."""
    keys = get_user_keys(email)
    env = {}
    # Always inject all keys the user has stored
    for name, value in keys.items():
        env[name] = value
    return env
