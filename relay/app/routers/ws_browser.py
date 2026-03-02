import asyncio
import json
import logging
import re
import time
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..auth import verify_token
from ..config import settings
from ..relay import hub

logger = logging.getLogger("relay.ws_browser")
router = APIRouter()

CLOUD_ALLOWED_ORIGINS = {"https://term.automaite.ca"}

# RFC 1918 private IP ranges + localhost for local mode
_PRIVATE_ORIGIN_RE = re.compile(
    r"^https?://"
    r"(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+)"
    r"(?::\d+)?$"
)

# Per-connection rate limiter: max messages per second
RATE_LIMIT_MAX = 100
RATE_LIMIT_WINDOW = 1.0  # seconds

# Input validation limits
MAX_WS_MESSAGE_BYTES = 65536  # 64KB
MAX_RESIZE_COLS = 500
MAX_RESIZE_ROWS = 200
MIN_RESIZE_COLS = 1
MIN_RESIZE_ROWS = 1


def _is_origin_allowed(origin: str) -> bool:
    if not origin:
        return True  # No origin header = same-origin
    if settings.mode == "local":
        return bool(_PRIVATE_ORIGIN_RE.match(origin))
    return origin in CLOUD_ALLOWED_ORIGINS


@router.websocket("/ws/terminal/{session_id}")
async def browser_websocket(ws: WebSocket, session_id: str):
    # Origin check
    origin = ws.headers.get("origin", "")
    if origin and not _is_origin_allowed(origin):
        await ws.close(code=4003, reason="Origin not allowed")
        return

    # Try cookie auth first — extract user email
    authenticated = False
    user_email = None
    cookie_token = ws.cookies.get(settings.cookie_name)
    if cookie_token:
        try:
            user_email = verify_token(cookie_token)
            authenticated = True
        except Exception:
            await ws.close(code=4001, reason="Unauthorized")
            return

    # Enforce session ownership
    session = hub.get_session(session_id, owner=user_email)
    if not session:
        await ws.close(code=4004, reason="Session not found")
        return

    await ws.accept()

    # If not authenticated via cookie, require first-message auth (fallback)
    if not authenticated:
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=5.0)
            msg = json.loads(raw)
            if msg.get("type") != "auth":
                await ws.close(code=4001, reason="Expected auth message")
                return
            user_email = verify_token(msg.get("token", ""))
            # Re-check session ownership with actual user
            session = hub.get_session(session_id, owner=user_email)
            if not session:
                await ws.close(code=4004, reason="Session not found")
                return
            await ws.send_text(json.dumps({"type": "auth_ok"}))
        except asyncio.TimeoutError:
            await ws.close(code=4001, reason="Auth timeout")
            return
        except Exception:
            await ws.close(code=4001, reason="Unauthorized")
            return

    # Disconnect previous browser for this session
    if session.browser_ws:
        try:
            await session.browser_ws.close(code=4002, reason="Replaced by new connection")
        except Exception:
            pass

    session.browser_ws = ws

    # Send buffered output
    if session.output_buffer:
        try:
            await ws.send_bytes(bytes(session.output_buffer))
        except Exception:
            pass

    # Server-side ping: send a WebSocket ping frame every 25s
    async def ping_loop():
        try:
            while True:
                await asyncio.sleep(25)
                await ws.send_bytes(b"\x00{\"type\":\"ping\"}")
        except Exception:
            pass

    ping_task = asyncio.create_task(ping_loop())

    # Rate limiter state
    msg_count = 0
    window_start = time.monotonic()

    try:
        while True:
            message = await ws.receive()

            if message["type"] == "websocket.disconnect":
                break

            # Input size validation
            raw_data = message.get("text") or message.get("bytes")
            if raw_data and len(raw_data) > MAX_WS_MESSAGE_BYTES:
                logger.warning("Oversized WS message from browser (%d bytes), dropping", len(raw_data))
                continue

            # Rate limiting
            now = time.monotonic()
            if now - window_start >= RATE_LIMIT_WINDOW:
                msg_count = 0
                window_start = now
            msg_count += 1
            if msg_count > RATE_LIMIT_MAX:
                await ws.close(code=4008, reason="Rate limit exceeded")
                break

            if "text" in message and message["text"]:
                data = json.loads(message["text"])
                msg_type = data.get("type")

                if msg_type == "input":
                    await hub.send_to_agent(
                        user_email,
                        {
                            "type": "input",
                            "session_id": session_id,
                            "data": data.get("data", ""),
                        },
                    )
                elif msg_type == "resize":
                    cols = data.get("cols", 80)
                    rows = data.get("rows", 24)
                    # Validate resize bounds
                    cols = max(MIN_RESIZE_COLS, min(MAX_RESIZE_COLS, int(cols)))
                    rows = max(MIN_RESIZE_ROWS, min(MAX_RESIZE_ROWS, int(rows)))
                    session.cols = cols
                    session.rows = rows
                    await hub.send_to_agent(
                        user_email,
                        {
                            "type": "resize",
                            "session_id": session_id,
                            "cols": cols,
                            "rows": rows,
                        },
                    )

    except WebSocketDisconnect:
        logger.debug("Browser disconnected from session %s", session_id)
    except Exception:
        logger.exception("Browser WebSocket error for session %s", session_id)
    finally:
        ping_task.cancel()
        if session.browser_ws is ws:
            session.browser_ws = None
