"""Bundled agent PTY manager.

Runs in-process within the desktop app. All configuration is passed as
function parameters instead of imported from a config module.
"""

import asyncio
import base64
import json
import re
import logging
import time

from .pty_manager import PtyManager
from .audit import log_event
from .crypto import E2EESession, load_device_secret, decrypt_credential

try:
    import websockets
except ImportError:
    raise ImportError("Install websockets: pip install websockets")

logger = logging.getLogger("agent")

# Defaults (same as the standalone agent)
DEFAULT_RECONNECT_MIN = 1
DEFAULT_RECONNECT_MAX = 30
DEFAULT_HEARTBEAT_INTERVAL = 15
DEFAULT_ALLOWED_COMMANDS = {
    "cmd.exe", "powershell.exe", "bash", "claudereal", "geminireal", "codexreal",
}
DEFAULT_SESSION_IDLE_TIMEOUT = 7200

# Only allow safe characters in commands
_SAFE_COMMAND_RE = re.compile(r'^[a-zA-Z0-9\s\-_./\\:="\']+$')


def validate_command(command: str, allowed: set[str]) -> bool:
    """Check if command is in the allowlist.

    Matches by base name (stripping .cmd/.bat/.exe extensions for Windows)
    or by full path if custom agent paths are in the allowlist.
    """
    if not command or not _SAFE_COMMAND_RE.match(command):
        return False
    first = command.strip().split()[0]
    allowed_lower = {c.lower() for c in allowed}
    # Check full path match (for custom agent paths)
    if first.lower() in allowed_lower:
        return True
    # Check base name match (strip path + Windows extensions)
    base = first.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".cmd", ".bat", ".exe", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base in allowed_lower


async def run_agent(
    relay_url: str,
    agent_key: str,
    *,
    shutdown_event: asyncio.Event | None = None,
    reconnect_min: int = DEFAULT_RECONNECT_MIN,
    reconnect_max: int = DEFAULT_RECONNECT_MAX,
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
    allowed_commands: set[str] | None = None,
    session_idle_timeout: int = DEFAULT_SESSION_IDLE_TIMEOUT,
):
    """Main agent loop — connects to relay and manages PTY sessions.

    Args:
        relay_url: WebSocket URL of the relay agent endpoint.
        agent_key: Bearer token for agent authentication.
        shutdown_event: Optional event to signal clean shutdown.
        reconnect_min: Minimum reconnect backoff in seconds.
        reconnect_max: Maximum reconnect backoff in seconds.
        heartbeat_interval: Seconds between heartbeat pings.
        allowed_commands: Set of allowed executable base names.
        session_idle_timeout: Seconds before idle sessions are killed (0=disabled).
    """
    if allowed_commands is None:
        allowed_commands = DEFAULT_ALLOWED_COMMANDS

    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    loop = asyncio.get_event_loop()
    pty_mgr = PtyManager(loop)
    e2ee_sessions: dict[str, E2EESession] = {}  # session_id → E2EESession
    # Pending credential requests: request_id → asyncio.Event
    credential_events: dict[str, asyncio.Event] = {}
    # Resolved credential responses: request_id → {"approved": bool, "credential": str | None}
    credential_results: dict[str, dict] = {}
    backoff = reconnect_min

    while not shutdown_event.is_set():
        try:
            logger.info("Connecting to relay: %s", relay_url)
            log_event("connecting", relay=relay_url)

            headers = {"Authorization": f"Bearer {agent_key}"}
            async with websockets.connect(
                relay_url, ping_interval=20, ping_timeout=10,
                additional_headers=headers,
            ) as ws:
                logger.info("Connected to relay")
                log_event("connected", relay=relay_url)
                backoff = reconnect_min

                # Report detected agents to relay
                try:
                    import auto_detect
                    agents = auto_detect.detect_agents()
                    await ws.send(json.dumps({
                        "type": "capabilities",
                        "agents": agents,
                    }))
                    logger.info("Sent capabilities: %s", [a["name"] for a in agents if a["installed"]])
                except Exception:
                    logger.warning("Failed to send capabilities", exc_info=True)

                tasks = [
                    asyncio.create_task(_output_sender(ws, pty_mgr, e2ee_sessions)),
                    asyncio.create_task(_send_heartbeats(ws, heartbeat_interval)),
                    asyncio.create_task(
                        _receive_commands(
                            ws, pty_mgr, allowed_commands, e2ee_sessions,
                            credential_events, credential_results,
                        )
                    ),
                    asyncio.create_task(shutdown_event.wait()),
                ]
                if session_idle_timeout > 0:
                    tasks.append(asyncio.create_task(
                        _idle_checker(ws, pty_mgr, session_idle_timeout)
                    ))

                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED,
                )

                for t in pending:
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass

                if shutdown_event.is_set():
                    break

        except (
            websockets.exceptions.ConnectionClosed,
            ConnectionRefusedError,
            OSError,
        ) as e:
            logger.warning("Connection lost: %s. Reconnecting in %ds...", e, backoff)
            log_event("disconnected", reason=str(e))
        except Exception:
            logger.exception("Unexpected error. Reconnecting in %ds...", backoff)

        if not shutdown_event.is_set():
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, reconnect_max)

    logger.info("Killing all PTY sessions")
    log_event("shutdown")
    pty_mgr.kill_all()


async def _receive_commands(
    ws, pty_mgr: PtyManager, allowed_commands: set[str],
    e2ee_sessions: dict[str, E2EESession],
    credential_events: dict[str, asyncio.Event],
    credential_results: dict[str, dict],
):
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        msg_type = msg.get("type")
        sid = msg.get("session_id")
        sid_short = sid[:8] if sid else "?"

        if msg_type == "credential_response":
            # Phone approved a credential request
            req_id = msg.get("request_id", "")
            encrypted = msg.get("encrypted_credential", "")
            credential_results[req_id] = {
                "approved": True,
                "encrypted_credential": encrypted,
            }
            event = credential_events.get(req_id)
            if event:
                event.set()
            logger.info("Credential approved for request %s", req_id[:8])
            log_event("credential_approved", request_id=req_id[:8])
            continue

        elif msg_type == "credential_denied":
            req_id = msg.get("request_id", "")
            credential_results[req_id] = {"approved": False, "encrypted_credential": None}
            event = credential_events.get(req_id)
            if event:
                event.set()
            logger.info("Credential denied for request %s", req_id[:8])
            log_event("credential_denied", request_id=req_id[:8])
            continue

        elif msg_type == "credential_expired":
            req_id = msg.get("request_id", "")
            credential_results[req_id] = {"approved": False, "encrypted_credential": None}
            event = credential_events.get(req_id)
            if event:
                event.set()
            logger.info("Credential request expired: %s", req_id[:8])
            log_event("credential_expired", request_id=req_id[:8])
            continue

        elif msg_type == "spawn":
            command = msg.get("command", "cmd.exe")
            cols = msg.get("cols", 80)
            rows = msg.get("rows", 24)
            extra_env = msg.get("env", {})

            # Set up E2EE if requested
            if msg.get("e2ee") and msg.get("device_id"):
                device_id = msg["device_id"]
                secret = load_device_secret(device_id)
                if secret:
                    e2ee_sessions[sid] = E2EESession(secret)
                    logger.info("E2EE enabled for session %s (device %s)", sid_short, device_id[:8])
                    log_event("e2ee_enabled", session_id=sid_short, device_id=device_id[:8])
                else:
                    logger.warning("E2EE requested but no secret for device %s", device_id[:8])

            if not validate_command(command, allowed_commands):
                logger.warning("BLOCKED disallowed command: %r", command)
                log_event("command_blocked", session_id=sid_short, command=command)
                base = command.strip().split()[0]
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "not_allowed", "command": base,
                }))
                continue

            # Check if the binary actually exists on PATH
            import shutil
            binary = command.strip().split()[0]
            if not shutil.which(binary):
                logger.warning("Binary not found: %r", binary)
                log_event("binary_not_found", session_id=sid_short, command=binary)
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "not_found", "command": binary,
                }))
                continue

            try:
                log_event("spawn", session_id=sid_short, command=command)
                pty_mgr.spawn(sid, command, cols, rows, extra_env=extra_env)
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "running",
                }))
            except Exception as e:
                logger.exception("Failed to spawn PTY for %s", sid)
                log_event("spawn_failed", session_id=sid_short, error=str(e))
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "spawn_failed", "error": str(e),
                }))

        elif msg_type == "input":
            data = msg.get("data", "")
            # Decrypt E2EE input if session has encryption
            e2ee = e2ee_sessions.get(sid)
            if e2ee and data:
                try:
                    encrypted_bytes = base64.b64decode(data)
                    decrypted = e2ee.decrypt(encrypted_bytes)
                    data = decrypted.decode("utf-8", errors="replace")
                except Exception:
                    logger.exception("E2EE decrypt failed for %s", sid_short)
                    continue
            logger.info("Input for %s: %r", sid_short, data[:50])
            pty_mgr.write(sid, data)

        elif msg_type == "resize":
            cols = msg.get("cols", 80)
            rows = msg.get("rows", 24)
            pty_mgr.resize(sid, cols, rows)

        elif msg_type == "kill":
            log_event("kill", session_id=sid_short)
            pty_mgr.kill(sid)
            e2ee_sessions.pop(sid, None)
            await ws.send(json.dumps({
                "type": "status", "session_id": sid, "status": "exited",
            }))


async def _output_sender(
    ws, pty_mgr: PtyManager, e2ee_sessions: dict[str, E2EESession],
):
    while True:
        session_id, data = await pty_mgr.output_queue.get()

        if data is None:
            await ws.send(json.dumps({
                "type": "status", "session_id": session_id, "status": "exited",
            }))
            pty_mgr.sessions.pop(session_id, None)
            e2ee_sessions.pop(session_id, None)
            log_event("session_exited", session_id=session_id[:8])
            continue

        # Encrypt output if E2EE is active for this session
        e2ee = e2ee_sessions.get(session_id)
        if e2ee:
            data = e2ee.encrypt(data)

        frame = session_id.encode("ascii") + data
        await ws.send(frame)


async def _send_heartbeats(ws, interval: int):
    while True:
        await asyncio.sleep(interval)
        try:
            await ws.send(json.dumps({"type": "heartbeat"}))
        except Exception:
            break


async def _idle_checker(ws, pty_mgr: PtyManager, timeout: int):
    """Kill PTY sessions that have been idle too long."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        for sid, session in list(pty_mgr.sessions.items()):
            idle_secs = now - session.last_activity
            if idle_secs > timeout:
                logger.info(
                    "Session %s idle for %ds (limit %ds), killing",
                    sid[:8], int(idle_secs), timeout,
                )
                log_event("idle_timeout", session_id=sid[:8], idle_seconds=int(idle_secs))
                pty_mgr.kill(sid)
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                }))


async def request_credential(
    ws,
    credential_name: str,
    reason: str,
    session_id: str,
    credential_events: dict[str, asyncio.Event],
    credential_results: dict[str, dict],
    *,
    scope: str = "read",
    ttl_seconds: int = 300,
    agent_id: str = "",
) -> str | None:
    """Request a credential from the phone vault.

    Sends a credential_request to the relay, waits for the phone to approve/deny.
    Returns the decrypted credential string on approval, None on denial/timeout.
    """
    import uuid
    request_id = str(uuid.uuid4())

    event = asyncio.Event()
    credential_events[request_id] = event

    await ws.send(json.dumps({
        "type": "credential_request",
        "request_id": request_id,
        "credential_name": credential_name,
        "reason": reason,
        "scope": scope,
        "ttl_seconds": ttl_seconds,
        "agent_id": agent_id,
        "session_id": session_id,
    }))

    logger.info(
        "Requesting credential %s for session %s (request %s)",
        credential_name, session_id[:8], request_id[:8],
    )
    log_event(
        "credential_requested",
        credential_name=credential_name,
        session_id=session_id[:8],
        request_id=request_id[:8],
    )

    try:
        await asyncio.wait_for(event.wait(), timeout=ttl_seconds)
    except asyncio.TimeoutError:
        logger.warning("Credential request %s timed out", request_id[:8])
        log_event("credential_timeout", request_id=request_id[:8])
        credential_events.pop(request_id, None)
        credential_results.pop(request_id, None)
        return None

    result = credential_results.pop(request_id, None)
    credential_events.pop(request_id, None)

    if not result or not result.get("approved"):
        return None

    encrypted_b64 = result.get("encrypted_credential")
    if not encrypted_b64:
        return None

    # Decrypt the E2EE credential blob — requires device_secret, no plaintext fallback
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        device_secret = _find_device_secret_for_session(session_id)
        if not device_secret:
            logger.error(
                "No device_secret for session %s — cannot decrypt credential (request %s)",
                session_id[:8], request_id[:8],
            )
            log_event("credential_decrypt_failed", request_id=request_id[:8], reason="no_device_secret")
            return None
        credential = decrypt_credential(device_secret, encrypted_bytes)
        log_event("credential_decrypted", request_id=request_id[:8])
        return credential
    except Exception:
        logger.exception("Failed to decrypt credential for request %s", request_id[:8])
        return None


def _find_device_secret_for_session(session_id: str) -> str | None:
    """Look up the device secret from local config.

    In the desktop agent, there's typically one paired device.
    Falls back to the first available device secret.
    """
    from pathlib import Path
    devices_path = Path.home() / ".automaite" / "devices.json"
    if not devices_path.exists():
        return None
    try:
        devices = json.loads(devices_path.read_text("utf-8"))
        if devices:
            return devices[0].get("device_secret")
    except Exception:
        logger.exception("Failed to read devices.json for credential decryption")
    return None
