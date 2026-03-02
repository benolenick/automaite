from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel as _BM
from ..auth import (
    check_rate_limit,
    record_failed_attempt,
    clear_rate_limit,
    verify_google_token,
    create_token,
    get_current_user,
    generate_nonce,
    verify_nonce,
    create_pairing_token,
    verify_pairing_token,
    register_device,
    verify_device_hmac,
    list_devices,
    revoke_device,
    create_app_token,
    exchange_app_token,
    create_device_code,
    poll_device_code,
    approve_device_code,
    create_agent_token,
)
from ..config import settings
from ..models import (
    GoogleLoginRequest,
    CreateSessionRequest,
    SessionInfo,
    PairRequest,
    PairResponse,
    DeviceAuthRequest,
    DeviceInfo,
    CreatePlaybookRequest,
    UpdatePlaybookRequest,
    PlaybookResponse,
)
from ..relay import hub
from .. import playbooks as pb_store
from .. import keystore
from .. import subscriptions

router = APIRouter(prefix="/api")

# Caddy's Docker bridge IP — only trust XFF from this source
CADDY_DOCKER_SUBNET = "172.18.0."


def _client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else "unknown"
    if peer_ip.startswith(CADDY_DOCKER_SUBNET) or peer_ip == "127.0.0.1":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer_ip


def _set_session_cookie(response: Response, token: str):
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.jwt_expire_days * 86400,
        path="/",
    )


# ── Public Config ──

@router.get("/config")
async def public_config():
    cfg = {"mode": settings.mode}
    if settings.mode == "cloud":
        cfg["google_client_id"] = settings.google_client_id
    return cfg


# ── Google OAuth (cloud mode only) ──

@router.post("/login")
async def login(body: GoogleLoginRequest, request: Request, response: Response):
    if settings.mode != "cloud":
        raise HTTPException(status_code=404, detail="Google login not available in local mode")

    ip = _client_ip(request)
    check_rate_limit(ip)

    if body.nonce is not None:
        if not verify_nonce(body.nonce):
            record_failed_attempt(ip)
            raise HTTPException(status_code=401, detail="Invalid or expired nonce")

    try:
        email = verify_google_token(body.credential, nonce=body.nonce)
    except HTTPException:
        record_failed_attempt(ip)
        raise
    clear_rate_limit(ip)
    token = create_token(email)
    _set_session_cookie(response, token)
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(
        key=settings.cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )
    return {"ok": True}


@router.get("/me")
async def me(user: str = Depends(get_current_user)):
    return {"email": user}


@router.get("/nonce")
async def get_nonce():
    return {"nonce": generate_nonce()}


# ── Device Pairing (local mode) ──

@router.get("/pairing-token")
async def get_pairing_token():
    if settings.mode != "local":
        raise HTTPException(status_code=404, detail="Pairing not available in cloud mode")
    return {"pairing_token": create_pairing_token()}


@router.post("/pair")
async def pair_device(body: PairRequest, request: Request, response: Response):
    if settings.mode != "local":
        raise HTTPException(status_code=404, detail="Pairing not available in cloud mode")

    ip = _client_ip(request)
    check_rate_limit(ip)

    if not verify_pairing_token(body.pairing_token):
        record_failed_attempt(ip)
        raise HTTPException(status_code=401, detail="Invalid or expired pairing token")

    clear_rate_limit(ip)
    device_secret = register_device(body.device_id, body.device_name)
    token = create_token(f"device:{body.device_id}")
    _set_session_cookie(response, token)
    return PairResponse(device_secret=device_secret)


@router.post("/auth/device")
async def auth_device(body: DeviceAuthRequest, request: Request, response: Response):
    ip = _client_ip(request)
    check_rate_limit(ip)

    if not verify_device_hmac(body.device_id, body.timestamp, body.hmac):
        record_failed_attempt(ip)
        raise HTTPException(status_code=401, detail="Invalid device credentials")

    clear_rate_limit(ip)
    token = create_token(f"device:{body.device_id}")
    _set_session_cookie(response, token)
    return {"ok": True}


@router.get("/devices", response_model=list[DeviceInfo])
async def get_devices(_user: str = Depends(get_current_user)):
    return [DeviceInfo(**d) for d in list_devices()]


@router.delete("/devices/{device_id}")
async def delete_device(device_id: str, _user: str = Depends(get_current_user)):
    if not revoke_device(device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    return {"ok": True}


# ── APK Download ──

@router.get("/download/app")
async def download_apk():
    apk_path = Path(__file__).parent.parent.parent / "static" / "app-debug.apk"
    if not apk_path.exists():
        raise HTTPException(status_code=404, detail="APK not found")
    return FileResponse(
        path=str(apk_path),
        media_type="application/vnd.android.package-archive",
        filename="automaite-terminal.apk",
    )


@router.get("/download/desktop")
async def download_desktop():
    exe_path = Path(__file__).parent.parent.parent / "static" / "automaite.exe"
    if not exe_path.exists():
        raise HTTPException(status_code=404, detail="Desktop agent not found")
    return FileResponse(
        path=str(exe_path),
        media_type="application/octet-stream",
        filename="automaite.exe",
    )


# ── App Login Bridge (WebView <-> Browser handoff) ──

@router.post("/app/token")
async def create_app_login_token(
    request: Request,
    user: str = Depends(get_current_user),
):
    jwt_token = create_token(user)
    token = create_app_token(jwt_token)
    return {"token": token}


@router.get("/app/exchange")
async def exchange_app_login_token(token: str):
    jwt_token = exchange_app_token(token)
    if jwt_token is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    resp = RedirectResponse(url="/", status_code=302)
    _set_session_cookie(resp, jwt_token)
    return resp


# ── Desktop Agent Device-Code Pairing ──

class _DeviceCodePollBody(_BM):
    device_code: str

class _DeviceCodeApproveBody(_BM):
    user_code: str

@router.post("/agent/device-code")
async def create_agent_device_code():
    """Desktop agent calls this to start the device_code flow. No auth required."""
    return create_device_code()


@router.post("/agent/poll")
async def poll_agent_device_code(body: _DeviceCodePollBody):
    """Desktop agent polls this until user approves. No auth required."""
    result = poll_device_code(body.device_code)
    if result is None:
        raise HTTPException(status_code=404, detail="Invalid or expired device code")
    if result == "pending":
        return {"status": "pending"}
    # result is the email — generate agent token
    token = create_agent_token(result)
    return {"status": "approved", "agent_token": token, "email": result}


@router.post("/agent/approve")
async def approve_agent_device_code(
    body: _DeviceCodeApproveBody, user: str = Depends(get_current_user)
):
    """Browser user approves a device code, linking it to their account."""
    ok = approve_device_code(body.user_code, user)
    if not ok:
        raise HTTPException(status_code=404, detail="Invalid or expired code")
    return {"ok": True}


# ── Sessions ──

@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(_user: str = Depends(get_current_user)):
    return [
        SessionInfo(
            session_id=s.session_id,
            agent_type=s.agent_type,
            label=s.label,
            status=s.status,
            command=s.command,
        )
        for s in hub.list_sessions(owner=_user)
    ]


@router.post("/sessions", response_model=SessionInfo)
async def create_session(
    body: CreateSessionRequest, _user: str = Depends(get_current_user)
):
    # Gate behind active subscription
    if not subscriptions.is_subscribed(_user):
        raise HTTPException(status_code=402, detail="Active subscription required")

    # Check agent is connected before creating session
    if not hub.agent_connected(_user):
        raise HTTPException(
            status_code=503,
            detail="Your desktop agent is not connected. Make sure automaite.exe is running on your computer.",
        )

    # Inject user API keys as env vars for the agent PTY
    session_env = keystore.get_env_for_session(_user, body.agent_type)

    session = hub.create_session(
        agent_type=body.agent_type,
        command=body.command,
        label=body.label,
        cols=body.cols,
        rows=body.rows,
        owner=_user,
        env=session_env,
    )

    spawn_msg = {
        "type": "spawn",
        "session_id": session.session_id,
        "command": session.command,
        "cols": session.cols,
        "rows": session.rows,
    }
    if session_env:
        spawn_msg["env"] = session_env

    await hub.send_to_agent(_user, spawn_msg)

    return SessionInfo(
        session_id=session.session_id,
        agent_type=session.agent_type,
        label=session.label,
        status=session.status,
        command=session.command,
    )


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, _user: str = Depends(get_current_user)):
    session = hub.get_session(session_id, owner=_user)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    await hub.send_to_agent(_user, {"type": "kill", "session_id": session_id})
    hub.remove_session(session_id, owner=_user)
    return {"ok": True}


@router.get("/agent-status")
async def agent_status(_user: str = Depends(get_current_user)):
    return {"connected": hub.agent_connected(_user)}


# ── User API Keys ──

class _SaveKeysBody(_BM):
    keys: dict[str, str] = {}


@router.get("/agents")
async def get_agents(_user: str = Depends(get_current_user)):
    """Return detected agent capabilities from the connected desktop agent."""
    agents = hub.get_agent_capabilities(_user)
    if not agents:
        # Return defaults with nothing installed
        return [
            {"name": "claude", "display_name": "Claude Code", "installed": False, "version": None,
             "install_cmd": "npm install -g @anthropic-ai/claude-code",
             "auth_type": "browser",
             "auth_instructions": "Run 'claude' once to sign in via your browser, or add your Anthropic API key in Settings."},
            {"name": "gemini", "display_name": "Gemini CLI", "installed": False, "version": None,
             "install_cmd": "npm install -g @google/gemini-cli",
             "auth_type": "api_key",
             "auth_instructions": "Add your Gemini API key in Settings. Get one at ai.google.dev"},
            {"name": "codex", "display_name": "Codex CLI", "installed": False, "version": None,
             "install_cmd": "npm install -g @openai/codex",
             "auth_type": "browser",
             "auth_instructions": "Run 'codex' once to sign in via your browser, or add your OpenAI API key in Settings."},
        ]
    # Enrich with setup info
    setup_info = {
        "claude": {
            "install_cmd": "npm install -g @anthropic-ai/claude-code",
            "auth_type": "browser",
            "auth_instructions": "Run 'claude' once to sign in via your browser, or add your Anthropic API key in Settings.",
        },
        "gemini": {
            "install_cmd": "npm install -g @google/gemini-cli",
            "auth_type": "api_key",
            "auth_instructions": "Add your Gemini API key in Settings. Get one at ai.google.dev",
        },
        "codex": {
            "install_cmd": "npm install -g @openai/codex",
            "auth_type": "browser",
            "auth_instructions": "Run 'codex' once to sign in via your browser, or add your OpenAI API key in Settings.",
        },
    }
    for a in agents:
        info = setup_info.get(a.get("name"), {})
        a.update(info)
    return agents


@router.post("/settings/keys")
async def save_keys(body: _SaveKeysBody, user: str = Depends(get_current_user)):
    keystore.save_user_keys(user, body.keys)
    return {"ok": True, "stored": keystore.get_user_key_names(user)}


@router.get("/settings/keys")
async def get_keys(user: str = Depends(get_current_user)):
    names = keystore.get_user_key_names(user)
    keys = keystore.get_user_keys(user)
    masked = {}
    for name in names:
        val = keys.get(name, "")
        if len(val) > 8:
            masked[name] = val[:4] + "..." + val[-4:]
        else:
            masked[name] = "****"
    return {"keys": masked}


# ── Stripe Subscriptions ──

@router.get("/subscription")
async def get_subscription(user: str = Depends(get_current_user)):
    info = subscriptions.get_subscription_info(user)
    return {
        "active": info.get("active", False),
        "stripe_publishable_key": subscriptions.STRIPE_PUBLISHABLE_KEY,
        "price_id": subscriptions.STRIPE_PRICE_ID,
    }


@router.post("/subscribe")
async def create_subscription(user: str = Depends(get_current_user)):
    url = subscriptions.create_checkout_session(
        email=user,
        success_url="https://term.automaite.ca/?subscribed=1&session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://term.automaite.ca/?canceled=1",
    )
    return {"url": url}


class _VerifySessionBody(_BM):
    session_id: str

@router.post("/subscription/verify")
async def verify_subscription(body: _VerifySessionBody, user: str = Depends(get_current_user)):
    ok = subscriptions.verify_checkout_session(body.session_id, user)
    return {"active": ok}


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        result = subscriptions.handle_webhook(payload, sig)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Playbooks ──

@router.get("/playbooks", response_model=list[PlaybookResponse])
async def list_playbooks(_user: str = Depends(get_current_user)):
    return [PlaybookResponse(**pb) for pb in pb_store.list_playbooks()]


@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(playbook_id: str, _user: str = Depends(get_current_user)):
    pb = pb_store.get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PlaybookResponse(**pb)


@router.post("/playbooks", response_model=PlaybookResponse)
async def create_playbook(
    body: CreatePlaybookRequest, _user: str = Depends(get_current_user)
):
    pb = pb_store.create_playbook(
        name=body.name,
        agent_type=body.agent_type,
        agent_config=body.agent_config,
        instructions=body.instructions,
    )
    return PlaybookResponse(**pb)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: str,
    body: UpdatePlaybookRequest,
    _user: str = Depends(get_current_user),
):
    pb = pb_store.update_playbook(
        playbook_id,
        name=body.name,
        agent_type=body.agent_type,
        agent_config=body.agent_config,
        instructions=body.instructions,
    )
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PlaybookResponse(**pb)


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: str, _user: str = Depends(get_current_user)
):
    if not pb_store.delete_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"ok": True}


# ── Credential Vault ──

from ..vault import vault_manager as _vault_mgr
from ..models import (
    CredentialRequestCreate, CredentialRequestInfo,
    CredentialResponseSubmit, VaultAuditResponse,
)


@router.post("/vault/request", response_model=CredentialRequestInfo)
async def vault_create_request(
    body: CredentialRequestCreate, user: str = Depends(get_current_user)
):
    req = _vault_mgr.create_request(
        credential_name=body.credential_name,
        reason=body.reason,
        scope=body.scope,
        ttl_seconds=body.ttl_seconds,
        agent_id=body.agent_id,
        session_id=body.session_id,
        user_email=user,
    )
    await hub.send_to_phone(user, {
        "type": "credential_request",
        "request_id": req.request_id,
        "credential_name": req.credential_name,
        "reason": req.reason,
        "scope": req.scope,
        "ttl_seconds": req.ttl_seconds,
        "agent_id": req.agent_id,
        "session_id": req.session_id,
    })
    return CredentialRequestInfo(
        request_id=req.request_id, credential_name=req.credential_name,
        reason=req.reason, scope=req.scope, ttl_seconds=req.ttl_seconds,
        agent_id=req.agent_id, session_id=req.session_id,
        status=req.status, created_at=req.created_at,
    )


@router.get("/vault/request/{request_id}", response_model=CredentialRequestInfo)
async def vault_get_request(request_id: str, user: str = Depends(get_current_user)):
    req = _vault_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    if req.user_email != user:
        raise HTTPException(status_code=403, detail="Not your credential request")
    return CredentialRequestInfo(
        request_id=req.request_id, credential_name=req.credential_name,
        reason=req.reason, scope=req.scope, ttl_seconds=req.ttl_seconds,
        agent_id=req.agent_id, session_id=req.session_id,
        status=req.status, created_at=req.created_at,
    )


@router.get("/vault/pending", response_model=list[CredentialRequestInfo])
async def vault_pending_requests(user: str = Depends(get_current_user)):
    pending = _vault_mgr.get_pending_for_user(user)
    return [
        CredentialRequestInfo(
            request_id=r.request_id, credential_name=r.credential_name,
            reason=r.reason, scope=r.scope, ttl_seconds=r.ttl_seconds,
            agent_id=r.agent_id, session_id=r.session_id,
            status=r.status, created_at=r.created_at,
        )
        for r in pending
    ]


@router.post("/vault/respond/{request_id}")
async def vault_respond(
    request_id: str,
    body: CredentialResponseSubmit,
    user: str = Depends(get_current_user),
):
    req = _vault_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    if req.user_email != user:
        raise HTTPException(status_code=403, detail="Not your credential request")
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request already {req.status}")

    if body.approved:
        import base64
        encrypted_bytes = base64.b64decode(body.encrypted_credential)
        await _vault_mgr.approve(request_id, encrypted_bytes)
        await hub.send_to_agent(user, {
            "type": "credential_response",
            "request_id": request_id,
            "encrypted_credential": body.encrypted_credential,
        })
        _vault_mgr.clear_credential(request_id)
    else:
        await _vault_mgr.deny(request_id)
        await hub.send_to_agent(user, {
            "type": "credential_denied",
            "request_id": request_id,
        })
    return {"ok": True}


@router.get("/vault/poll/{request_id}")
async def vault_poll(request_id: str, _user: str = Depends(get_current_user)):
    req = _vault_mgr.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    result = {"request_id": request_id, "status": req.status}
    if req.status == "approved" and req.encrypted_credential:
        import base64
        result["encrypted_credential"] = base64.b64encode(req.encrypted_credential).decode()
    return result


@router.get("/vault/audit", response_model=list[VaultAuditResponse])
async def vault_audit(user: str = Depends(get_current_user), limit: int = 50):
    entries = _vault_mgr.get_audit_log(user, limit=limit)
    return [
        VaultAuditResponse(
            request_id=e.request_id, credential_name=e.credential_name,
            agent_id=e.agent_id, session_id=e.session_id,
            action=e.action, timestamp=e.timestamp,
        )
        for e in entries
    ]
