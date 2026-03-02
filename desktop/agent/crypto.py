"""E2EE crypto module for the agent side.

Uses HKDF-SHA256 to derive an AES-256-GCM key from the shared device_secret,
then encrypts/decrypts terminal I/O so the relay is zero-knowledge.
"""

import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("agent.crypto")

_E2EE_SALT = b"automaite-e2ee-v1"
_E2EE_INFO = b"aes-key"
_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM


def derive_key(device_secret: str) -> bytes:
    """Derive a 32-byte AES-256-GCM key from the device_secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_E2EE_SALT,
        info=_E2EE_INFO,
    )
    return hkdf.derive(device_secret.encode("utf-8"))


class E2EESession:
    """Encrypt/decrypt terminal I/O for a single session."""

    def __init__(self, device_secret: str):
        self._key = derive_key(device_secret)
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext → nonce (12 bytes) + ciphertext + GCM tag (16 bytes)."""
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt nonce + ciphertext + tag → plaintext."""
        if len(blob) < _NONCE_SIZE + 16:
            raise ValueError("E2EE blob too short")
        nonce = blob[:_NONCE_SIZE]
        ciphertext = blob[_NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ciphertext, None)


def decrypt_credential(device_secret: str, encrypted_blob: bytes) -> str:
    """Decrypt an E2EE credential blob from the phone vault.

    Returns the plaintext credential string.
    Raises ValueError on decryption failure.
    """
    key = derive_key(device_secret)
    aesgcm = AESGCM(key)
    if len(encrypted_blob) < _NONCE_SIZE + 16:
        raise ValueError("Credential blob too short")
    nonce = encrypted_blob[:_NONCE_SIZE]
    ciphertext = encrypted_blob[_NONCE_SIZE:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Credential decryption failed: {e}") from e


def load_device_secret(device_id: str) -> str | None:
    """Look up device_secret from ~/.automaite/devices.json."""
    devices_path = Path.home() / ".automaite" / "devices.json"
    if not devices_path.exists():
        logger.warning("devices.json not found at %s", devices_path)
        return None
    try:
        devices = json.loads(devices_path.read_text("utf-8"))
        for dev in devices:
            if dev.get("device_id") == device_id:
                return dev.get("device_secret")
    except Exception:
        logger.exception("Failed to read devices.json")
    return None
