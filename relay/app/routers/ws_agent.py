import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..auth import verify_agent_token
from ..relay import hub
from ..vault import vault_manager

logger = logging.getLogger("relay.ws_agent")
router = APIRouter()

MAX_MESSAGE_BYTES = 65536

@router.websocket("/ws/agent")
async def agent_websocket(ws: WebSocket):
    auth_header = ws.headers.get("authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    email = verify_agent_token(token)
    if not email:
        await ws.close(code=4001, reason="Invalid agent token")
        return

    await ws.accept()
    await hub.set_agent(email, ws)
    logger.info("Agent connected for %s", email)

    for s in hub.list_sessions(owner=email):
        if s.status in ("pending", "running"):
            logger.info("Re-spawning session %s on reconnected agent", s.session_id)
            s.status = "pending"
            respawn = {
                "type": "spawn", "session_id": s.session_id,
                "command": s.command, "cols": s.cols, "rows": s.rows,
            }
            if s.session_env:
                respawn["env"] = s.session_env
            await ws.send_json(respawn)

    try:
        while True:
            message = await ws.receive()
            if message["type"] == "websocket.disconnect":
                break

            if "bytes" in message and message["bytes"]:
                raw = message["bytes"]
                if len(raw) > MAX_MESSAGE_BYTES:
                    logger.warning("Agent sent oversized binary frame (%d bytes), dropping", len(raw))
                    continue
                if len(raw) > 36:
                    sid = raw[:36].decode("ascii", errors="replace")
                    data = raw[36:]
                    await hub.send_to_browser(sid, data)

            elif "text" in message and message["text"]:
                text = message["text"]
                if len(text.encode()) > MAX_MESSAGE_BYTES:
                    logger.warning("Agent sent oversized text frame (%d bytes), dropping", len(text.encode()))
                    continue
                data = json.loads(text)
                msg_type = data.get("type")

                if msg_type == "status":
                    sid = data.get("session_id")
                    status = data.get("status", "exited")
                    session = hub.get_session(sid)
                    if session:
                        session.status = status
                        session.exit_reason = data.get("reason", "")
                        session.exit_command = data.get("command", "")
                        if session.browser_ws:
                            try:
                                fwd = {"type": "status", "status": status}
                                if data.get("reason"): fwd["reason"] = data["reason"]
                                if data.get("command"): fwd["command"] = data["command"]
                                if data.get("error"): fwd["error"] = data["error"]
                                status_msg = json.dumps(fwd).encode()
                                await session.browser_ws.send_bytes(b"\x00" + status_msg)
                            except Exception:
                                pass

                elif msg_type == "capabilities":
                    agents = data.get("agents", [])
                    hub.set_agent_capabilities(email, agents)
                    logger.info("Agent capabilities for %s: %s",
                                email, [a.get("name") for a in agents if a.get("installed")])

                elif msg_type == "credential_request":
                    req_id = data.get("request_id", "")
                    cred_name = data.get("credential_name", "")
                    reason = data.get("reason", "")
                    scope = data.get("scope", "read")
                    ttl = data.get("ttl_seconds", 300)
                    agent_id = data.get("agent_id", "")
                    session_id = data.get("session_id", "")
                    session = hub.get_session(session_id)
                    user_email_for_cred = session.owner if session else email
                    req = vault_manager.create_request(
                        credential_name=cred_name,
                        reason=reason,
                        scope=scope,
                        ttl_seconds=ttl,
                        agent_id=agent_id,
                        session_id=session_id,
                        user_email=user_email_for_cred,
                        request_id=req_id,
                    )
                    await hub.send_to_phone(user_email_for_cred, {
                        "type": "credential_request",
                        "request_id": req.request_id,
                        "credential_name": cred_name,
                        "reason": reason,
                        "scope": scope,
                        "ttl_seconds": ttl,
                        "agent_id": agent_id,
                        "session_id": session_id,
                    })
                    logger.info("Credential request %s routed to phone for %s",
                                req.request_id[:8], user_email_for_cred)

                elif msg_type == "heartbeat":
                    pass

    except WebSocketDisconnect:
        logger.info("Agent disconnected for %s", email)
    except Exception:
        logger.exception("Agent WebSocket error for %s", email)
    finally:
        await hub.remove_agent(email)
        for s in hub.list_sessions(owner=email):
            if s.status == "running":
                s.status = "exited"
