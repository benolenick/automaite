import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jose import jwt, JWTError
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings

logger = logging.getLogger("relay.auth")
security = HTTPBearer(auto_error=False)

_rate_limit: dict[str, dict] = {}
MAX_ATTEMPTS = 5
BLOCK_DURATION = timedelta(hours=24)

_nonce_store: dict[str, float] = {}
NONCE_EXPIRY_SECONDS = 300

AUTOMAITE_DIR = Path.home() / ".automaite"
DEVICES_FILE = AUTOMAITE_DIR / "devices.json"
HMAC_MAX_DRIFT = 300

def generate_nonce() -> str:
    _cleanup_expired_nonces()
    nonce = secrets.token_urlsafe(32)
    _nonce_store[nonce] = time.time() + NONCE_EXPIRY_SECONDS
    return nonce

def verify_nonce(nonce: str) -> bool:
    _cleanup_expired_nonces()
    expiry = _nonce_store.pop(nonce, None)
    if expiry is None:
        return False
    return time.time() < expiry

def _cleanup_expired_nonces():
    now = time.time()
    expired = [k for k, v in _nonce_store.items() if v <= now]
    for k in expired:
        del _nonce_store[k]

def check_rate_limit(ip: str):
    entry = _rate_limit.get(ip)
    if not entry:
        return
    if entry.get("blocked_until") and entry["blocked_until"] > datetime.now(timezone.utc):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
    if entry.get("blocked_until") and entry["blocked_until"] <= datetime.now(timezone.utc):
        del _rate_limit[ip]

def record_failed_attempt(ip: str):
    entry = _rate_limit.setdefault(ip, {"attempts": 0, "blocked_until": None})
    entry["attempts"] += 1
    if entry["attempts"] >= MAX_ATTEMPTS:
        entry["blocked_until"] = datetime.now(timezone.utc) + BLOCK_DURATION

def clear_rate_limit(ip: str):
    _rate_limit.pop(ip, None)

def verify_google_token(id_token_str: str, nonce: str | None = None) -> str:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    try:
        payload = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), settings.google_client_id,
        )
    except ValueError as e:
        logger.warning("Google token verification failed: %s", e)
        raise HTTPException(status_code=401, detail="Invalid Google token")
    if not payload.get("email_verified"):
        raise HTTPException(status_code=401, detail="Google email not verified")
    if nonce is not None:
        token_nonce = payload.get("nonce")
        if token_nonce != nonce:
            raise HTTPException(status_code=401, detail="Invalid nonce")
    email = payload.get("email", "")
    if not email:
        raise HTTPException(status_code=401, detail="No email in token")
    return email

def create_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_expire_days)
    return jwt.encode(
        {"sub": subject, "exp": expire},
        settings.jwt_secret, algorithm=settings.jwt_algorithm,
    )

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return sub
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str:
    cookie_token = request.cookies.get(settings.cookie_name)
    if cookie_token:
        return verify_token(cookie_token)
    if credentials:
        return verify_token(credentials.credentials)
    raise HTTPException(status_code=401, detail="Not authenticated")

def verify_agent_key(key: str) -> bool:
    return secrets.compare_digest(key, settings.agent_key)

def _load_devices() -> dict:
    if not DEVICES_FILE.exists():
        return {}
    try:
        return json.loads(DEVICES_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

def _save_devices(devices: dict):
    AUTOMAITE_DIR.mkdir(parents=True, exist_ok=True)
    DEVICES_FILE.write_text(json.dumps(devices, indent=2))

def create_pairing_token() -> str:
    return generate_nonce()

def verify_pairing_token(token: str) -> bool:
    return verify_nonce(token)

def register_device(device_id: str, device_name: str) -> str:
    device_secret = secrets.token_urlsafe(32)
    devices = _load_devices()
    devices[device_id] = {
        "device_name": device_name,
        "device_secret": device_secret,
        "paired_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_devices(devices)
    logger.info("Device paired: %s (%s)", device_name, device_id)
    return device_secret

def verify_device_hmac(device_id: str, timestamp: int, provided_hmac: str) -> bool:
    now = int(time.time())
    if abs(now - timestamp) > HMAC_MAX_DRIFT:
        return False
    devices = _load_devices()
    device = devices.get(device_id)
    if not device:
        return False
    stored_secret = device.get("device_secret", "")
    if not stored_secret:
        return False
    expected = hmac.new(
        stored_secret.encode(), str(timestamp).encode(), hashlib.sha256
    ).hexdigest()
    return secrets.compare_digest(expected, provided_hmac)

def list_devices() -> list[dict]:
    devices = _load_devices()
    return [
        {"device_id": did, "device_name": info["device_name"], "paired_at": info["paired_at"]}
        for did, info in devices.items()
    ]

def revoke_device(device_id: str) -> bool:
    devices = _load_devices()
    if device_id not in devices:
        return False
    del devices[device_id]
    _save_devices(devices)
    return True

_app_tokens: dict[str, dict] = {}
APP_TOKEN_EXPIRY = 60

def create_app_token(jwt_token: str) -> str:
    _cleanup_app_tokens()
    token = secrets.token_urlsafe(32)
    _app_tokens[token] = {"jwt": jwt_token, "expires": time.time() + APP_TOKEN_EXPIRY}
    return token

def exchange_app_token(token: str) -> str | None:
    _cleanup_app_tokens()
    entry = _app_tokens.pop(token, None)
    if entry is None:
        return None
    if time.time() > entry["expires"]:
        return None
    return entry["jwt"]

def _cleanup_app_tokens():
    now = time.time()
    expired = [k for k, v in _app_tokens.items() if v["expires"] <= now]
    for k in expired:
        del _app_tokens[k]


# --- Agent Token Functions ---

def create_agent_token(email: str) -> str:
    """Create a long-lived JWT for desktop agent authentication.
    Scope 'agent' distinguishes it from regular user tokens."""
    expire = datetime.now(timezone.utc) + timedelta(days=365)
    return jwt.encode(
        {"sub": email, "scope": "agent", "exp": expire},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

def verify_agent_token(token: str) -> str | None:
    """Verify an agent token. Returns email if valid, None if invalid.
    Also accepts the legacy AGENT_KEY for backward compatibility."""
    # Check legacy AGENT_KEY first
    if token and secrets.compare_digest(token, settings.agent_key):
        return settings.auth_email
    # Try JWT
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        if payload.get("scope") != "agent":
            return None
        return payload.get("sub")
    except JWTError:
        return None


# --- Device Code Flow (OAuth device authorization pattern) ---

# In-memory device code store: {device_code: {"user_code": str, "email": str|None, "expires": float}}
_device_codes: dict[str, dict] = {}
DEVICE_CODE_EXPIRY = 300  # 5 minutes

def create_device_code() -> dict:
    """Create a device code pair for desktop agent pairing."""
    _cleanup_device_codes()
    device_code = secrets.token_urlsafe(32)
    # Human-readable code: XXXX-YYYY format
    user_code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
    _device_codes[device_code] = {
        "user_code": user_code,
        "email": None,  # Set when user approves
        "expires": time.time() + DEVICE_CODE_EXPIRY,
    }
    return {
        "device_code": device_code,
        "user_code": user_code,
        "expires_in": DEVICE_CODE_EXPIRY,
    }

def poll_device_code(device_code: str) -> str | None:
    """Poll a device code. Returns 'pending', email string if approved, or None if invalid/expired."""
    _cleanup_device_codes()
    entry = _device_codes.get(device_code)
    if entry is None:
        return None
    if time.time() > entry["expires"]:
        del _device_codes[device_code]
        return None
    if entry["email"] is not None:
        email = entry["email"]
        del _device_codes[device_code]  # One-time use
        return email
    return "pending"

def approve_device_code(user_code: str, email: str) -> bool:
    """Approve a device code by user_code. Returns True if found and approved."""
    _cleanup_device_codes()
    for dc, entry in _device_codes.items():
        if entry["user_code"] == user_code and entry["email"] is None:
            entry["email"] = email
            return True
    return False

def _cleanup_device_codes():
    now = time.time()
    expired = [k for k, v in _device_codes.items() if v["expires"] <= now]
    for k in expired:
        del _device_codes[k]
