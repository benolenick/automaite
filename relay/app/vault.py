"""Vault credential request state machine. The relay is a BLIND router — it
never decrypts or inspects credential blobs; it only shuttles E2EE bytes
between agents and the user's phone."""

import asyncio
import time
import uuid
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("relay")

MAX_AUDIT_ENTRIES = 10_000


@dataclass
class VaultRequest:
    request_id: str
    credential_name: str
    reason: str
    scope: str
    ttl_seconds: int
    agent_id: str
    session_id: str
    user_email: str
    status: str  # "pending" | "approved" | "denied" | "expired"
    created_at: float
    encrypted_credential: bytes | None = None
    responded_at: float | None = None


@dataclass
class VaultAuditEntry:
    request_id: str
    credential_name: str
    agent_id: str
    session_id: str
    user_email: str
    action: str  # "requested" | "approved" | "denied" | "expired"
    timestamp: float


class VaultManager:
    def __init__(self):
        self._requests: dict[str, VaultRequest] = {}
        self._audit: list[VaultAuditEntry] = []
        self._events: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    def create_request(
        self,
        credential_name: str,
        reason: str,
        scope: str,
        ttl_seconds: int,
        agent_id: str,
        session_id: str,
        user_email: str,
        request_id: str | None = None,
    ) -> VaultRequest:
        request_id = request_id or str(uuid.uuid4())
        req = VaultRequest(
            request_id=request_id,
            credential_name=credential_name,
            reason=reason,
            scope=scope,
            ttl_seconds=ttl_seconds,
            agent_id=agent_id,
            session_id=session_id,
            user_email=user_email,
            status="pending",
            created_at=time.time(),
        )
        self._requests[request_id] = req
        self._events[request_id] = asyncio.Event()
        self._add_audit(request_id, "requested")
        logger.info(
            "vault: request %s created by agent=%s user=%s cred=%s",
            request_id, agent_id, user_email, credential_name,
        )
        return req

    def get_request(self, request_id: str) -> VaultRequest | None:
        return self._requests.get(request_id)

    def get_pending_for_user(self, user_email: str) -> list[VaultRequest]:
        return [
            r for r in self._requests.values()
            if r.user_email == user_email and r.status == "pending"
        ]

    async def approve(self, request_id: str, encrypted_credential: bytes):
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                logger.warning("vault: approve called on unknown request %s", request_id)
                return
            if req.status != "pending":
                logger.warning(
                    "vault: approve called on non-pending request %s (status=%s)",
                    request_id, req.status,
                )
                return
            req.status = "approved"
            req.encrypted_credential = encrypted_credential
            req.responded_at = time.time()
        self._add_audit(request_id, "approved")
        event = self._events.get(request_id)
        if event:
            event.set()
        logger.info("vault: request %s approved", request_id)

    async def deny(self, request_id: str):
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                logger.warning("vault: deny called on unknown request %s", request_id)
                return
            if req.status != "pending":
                logger.warning(
                    "vault: deny called on non-pending request %s (status=%s)",
                    request_id, req.status,
                )
                return
            req.status = "denied"
            req.responded_at = time.time()
        self._add_audit(request_id, "denied")
        event = self._events.get(request_id)
        if event:
            event.set()
        logger.info("vault: request %s denied", request_id)

    async def wait_for_response(self, request_id: str, timeout: float) -> VaultRequest:
        event = self._events.get(request_id)
        if event is None:
            raise KeyError(f"No vault request with id {request_id!r}")

        try:
            await asyncio.wait_for(asyncio.shield(event.wait()), timeout=timeout)
        except asyncio.TimeoutError:
            async with self._lock:
                req = self._requests.get(request_id)
                if req and req.status == "pending":
                    req.status = "expired"
                    req.responded_at = time.time()
            self._add_audit(request_id, "expired")
            logger.info("vault: request %s expired after %.0fs", request_id, timeout)

        req = self._requests[request_id]
        self._events.pop(request_id, None)
        return req

    def expire_stale(self):
        now = time.time()
        for req in list(self._requests.values()):
            if req.status == "pending" and (now - req.created_at) > req.ttl_seconds:
                req.status = "expired"
                req.responded_at = now
                self._add_audit(req.request_id, "expired")
                event = self._events.pop(req.request_id, None)
                if event:
                    event.set()
                logger.info("vault: request %s expired (stale sweep)", req.request_id)

    def clear_credential(self, request_id: str):
        """Wipe the encrypted credential blob from memory after it has been forwarded."""
        req = self._requests.get(request_id)
        if req:
            req.encrypted_credential = None

    def get_audit_log(self, user_email: str, limit: int = 50) -> list[VaultAuditEntry]:
        entries = [e for e in self._audit if e.user_email == user_email]
        return entries[-limit:]

    def _add_audit(self, request_id: str, action: str):
        req = self._requests.get(request_id)
        if req is None:
            return
        entry = VaultAuditEntry(
            request_id=request_id,
            credential_name=req.credential_name,
            agent_id=req.agent_id,
            session_id=req.session_id,
            user_email=req.user_email,
            action=action,
            timestamp=time.time(),
        )
        self._audit.append(entry)
        if len(self._audit) > MAX_AUDIT_ENTRIES:
            self._audit = self._audit[-MAX_AUDIT_ENTRIES:]


vault_manager = VaultManager()
