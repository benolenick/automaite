"""Automaite Linux server agent.

Connects to the relay, manages PTY sessions on the host.
Auth: AGENT_KEY (Bearer token — legacy fallback accepted by relay's verify_agent_token).
"""

import asyncio
import json
import logging
import os
import re
import shutil
import time

from pty_linux import PtyManager

logger = logging.getLogger("agent")

ALLOWED_COMMANDS = {"bash", "sh", "claude", "gemini", "codex"}
_SAFE_COMMAND_RE = re.compile(r'^[a-zA-Z0-9\s\-_./\\:="\'@]+$')

HEARTBEAT_INTERVAL = 15
RECONNECT_MIN = 2
RECONNECT_MAX = 60


def _detect_agents() -> list[dict]:
    results = []
    for name, display in [
        ("claude", "Claude Code"),
        ("gemini", "Gemini CLI"),
        ("codex", "Codex CLI"),
    ]:
        path = shutil.which(name)
        results.append({
            "name": name,
            "display_name": display,
            "installed": bool(path),
            "version": None,
            "path": path,
        })
    return results


def _validate_command(command: str) -> bool:
    if not command or not _SAFE_COMMAND_RE.match(command):
        return False
    first = command.strip().split()[0]
    base = first.rsplit("/", 1)[-1].lower()
    return base in ALLOWED_COMMANDS


async def run(relay_url: str, agent_key: str):
    loop = asyncio.get_event_loop()
    pty_mgr = PtyManager(loop)
    backoff = RECONNECT_MIN

    while True:
        try:
            import websockets
            logger.info("Connecting to %s", relay_url)
            headers = {"Authorization": f"Bearer {agent_key}"}
            async with websockets.connect(
                relay_url,
                ping_interval=20,
                ping_timeout=10,
                extra_headers=headers,
            ) as ws:
                logger.info("Connected to relay")
                backoff = RECONNECT_MIN

                # Report capabilities on connect
                await ws.send(json.dumps({
                    "type": "capabilities",
                    "agents": _detect_agents(),
                }))
                logger.info("Capabilities sent")

                tasks = [
                    asyncio.create_task(_output_sender(ws, pty_mgr)),
                    asyncio.create_task(_heartbeat(ws)),
                    asyncio.create_task(_receive(ws, pty_mgr)),
                ]
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for t in pending:
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass

        except Exception as e:
            logger.warning("Connection error: %s. Reconnecting in %ds", e, backoff)

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, RECONNECT_MAX)


async def _receive(ws, pty_mgr: PtyManager):
    async for raw in ws:
        if isinstance(raw, bytes):
            continue
        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        msg_type = msg.get("type")
        sid = msg.get("session_id", "")

        if msg_type == "spawn":
            command = msg.get("command", "bash")
            cols = msg.get("cols", 80)
            rows = msg.get("rows", 24)
            extra_env = msg.get("env", {})

            if not _validate_command(command):
                logger.warning("Blocked disallowed command: %r", command)
                base = command.strip().split()[0].rsplit("/", 1)[-1]
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "not_allowed", "command": base,
                }))
                continue

            binary = command.strip().split()[0]
            if not shutil.which(binary):
                logger.warning("Binary not found: %r", binary)
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "not_found", "command": binary,
                }))
                continue

            try:
                pty_mgr.spawn(sid, command, cols, rows, extra_env=extra_env)
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "running",
                }))
            except Exception as e:
                logger.exception("Spawn failed for session %s", sid[:8])
                await ws.send(json.dumps({
                    "type": "status", "session_id": sid, "status": "exited",
                    "reason": "spawn_failed", "error": str(e),
                }))

        elif msg_type == "input":
            pty_mgr.write(sid, msg.get("data", ""))

        elif msg_type == "resize":
            pty_mgr.resize(sid, msg.get("cols", 80), msg.get("rows", 24))

        elif msg_type == "kill":
            pty_mgr.kill(sid)
            await ws.send(json.dumps({
                "type": "status", "session_id": sid, "status": "exited",
            }))


async def _output_sender(ws, pty_mgr: PtyManager):
    while True:
        sid, data = await pty_mgr.output_queue.get()
        if data is None:
            await ws.send(json.dumps({
                "type": "status", "session_id": sid, "status": "exited",
            }))
            pty_mgr.sessions.pop(sid, None)
        else:
            frame = sid.encode("ascii") + data
            await ws.send(frame)


async def _heartbeat(ws):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        await ws.send(json.dumps({"type": "heartbeat"}))
