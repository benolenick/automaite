"""WebSocket endpoint for phone (Android/iOS) vault connections."""

import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..auth import verify_token
from ..config import settings
from ..relay import hub
from ..vault import vault_manager

logger = logging.getLogger("relay.ws_phone")
router = APIRouter()


@router.websocket("/ws/phone")
async def phone_websocket(ws: WebSocket):
    cookie_token = ws.cookies.get(settings.cookie_name)
    if not cookie_token:
        await ws.close(code=4001, reason="Unauthorized")
        return

    try:
        user_email = verify_token(cookie_token)
    except Exception:
        await ws.close(code=4001, reason="Unauthorized")
        return

    await ws.accept()
    await hub.set_phone(user_email, ws)
    logger.info("Phone connected for user %s", user_email)

    pending = vault_manager.get_pending_for_user(user_email)
    for req in pending:
        try:
            await ws.send_json({
                "type": "credential_request",
                "request_id": req.request_id,
                "credential_name": req.credential_name,
                "reason": req.reason,
                "scope": req.scope,
                "ttl_seconds": req.ttl_seconds,
                "agent_id": req.agent_id,
                "session_id": req.session_id,
            })
        except Exception:
            break

    try:
        while True:
            message = await ws.receive()
            if message["type"] == "websocket.disconnect":
                break
            if "text" in message and message["text"]:
                data = json.loads(message["text"])
                msg_type = data.get("type")

                if msg_type == "credential_response":
                    request_id = data.get("request_id", "")
                    req_obj = vault_manager.get_request(request_id)
                    if req_obj and req_obj.user_email != user_email:
                        logger.warning("vault: cross-user response attempt by %s", user_email)
                        continue
                    encrypted = data.get("encrypted_credential", "")
                    import base64
                    encrypted_bytes = base64.b64decode(encrypted)
                    await vault_manager.approve(request_id, encrypted_bytes)
                    await hub.send_to_agent(user_email, {
                        "type": "credential_response",
                        "request_id": request_id,
                        "encrypted_credential": encrypted,
                    })
                    vault_manager.clear_credential(request_id)
                    logger.info("Credential approved via phone WS: %s", request_id[:8])

                elif msg_type == "credential_denied":
                    request_id = data.get("request_id", "")
                    req_obj = vault_manager.get_request(request_id)
                    if req_obj and req_obj.user_email != user_email:
                        logger.warning("vault: cross-user denied attempt by %s", user_email)
                        continue
                    await vault_manager.deny(request_id)
                    await hub.send_to_agent(user_email, {
                        "type": "credential_denied",
                        "request_id": request_id,
                    })
                    logger.info("Credential denied via phone WS: %s", request_id[:8])

    except WebSocketDisconnect:
        logger.info("Phone disconnected for user %s", user_email)
    except Exception:
        logger.exception("Phone WebSocket error for user %s", user_email)
    finally:
        if hub.phone_ws.get(user_email) is ws:
            await hub.set_phone(user_email, None)
