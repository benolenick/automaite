import asyncio
import uuid
import json
import logging
from dataclasses import dataclass, field
from fastapi import HTTPException, WebSocket

logger = logging.getLogger("relay")

DEFAULT_SESSION_IDLE_TIMEOUT = 7200
MAX_SESSIONS = 10


@dataclass
class Session:
    session_id: str
    agent_type: str
    label: str
    command: str
    cols: int
    rows: int
    owner: str
    status: str = "pending"
    exit_reason: str = ""
    exit_command: str = ""
    session_env: dict = field(default_factory=dict)
    browser_ws: WebSocket | None = None
    output_buffer: bytearray = field(default_factory=bytearray)
    MAX_BUFFER = 256 * 1024

    def append_output(self, data: bytes):
        self.output_buffer.extend(data)
        if len(self.output_buffer) > self.MAX_BUFFER:
            self.output_buffer = self.output_buffer[-self.MAX_BUFFER:]


class RelayHub:
    def __init__(self):
        self.sessions: dict[str, Session] = {}
        self.agent_connections: dict[str, WebSocket] = {}
        self.agent_capabilities: dict[str, list] = {}  # email → agent list
        self.phone_ws: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    def agent_connected(self, email: str) -> bool:
        return email in self.agent_connections

    def set_agent_capabilities(self, email: str, agents: list):
        self.agent_capabilities[email] = agents

    def get_agent_capabilities(self, email: str) -> list:
        return self.agent_capabilities.get(email, [])

    async def set_agent(self, email: str, ws: WebSocket):
        async with self._lock:
            self.agent_connections[email] = ws

    async def remove_agent(self, email: str):
        async with self._lock:
            self.agent_connections.pop(email, None)

    async def set_phone(self, email: str, ws):
        async with self._lock:
            if ws is None:
                self.phone_ws.pop(email, None)
            else:
                self.phone_ws[email] = ws

    async def send_to_phone(self, email: str, message: dict):
        ws = self.phone_ws.get(email)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                logger.debug('Failed to send to phone for %s', email)

    def create_session(self, agent_type: str, command: str, label: str, cols: int, rows: int, owner: str, env: dict | None = None) -> Session:
        owner_sessions = [s for s in self.sessions.values() if s.owner == owner]
        if len(owner_sessions) >= MAX_SESSIONS:
            raise HTTPException(status_code=429, detail="Maximum session limit reached")
        sid = str(uuid.uuid4())
        session = Session(
            session_id=sid,
            agent_type=agent_type,
            label=label or f"{agent_type}-{sid[:6]}",
            command=command,
            cols=cols,
            rows=rows,
            owner=owner,
        )
        session.session_env = env or {}
        self.sessions[sid] = session
        return session

    def get_session(self, sid: str, owner: str | None = None) -> Session | None:
        session = self.sessions.get(sid)
        if session is None:
            return None
        if owner is not None and session.owner != owner:
            return None
        return session

    def list_sessions(self, owner: str) -> list[Session]:
        return [s for s in self.sessions.values() if s.owner == owner]

    def remove_session(self, sid: str, owner: str | None = None):
        session = self.sessions.get(sid)
        if session is None:
            return
        if owner is not None and session.owner != owner:
            return
        self.sessions.pop(sid, None)

    async def send_to_agent(self, owner: str, message: dict):
        ws = self.agent_connections.get(owner)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                logger.exception("Failed to send to agent for owner %s", owner)
        else:
            logger.warning("Cannot send to agent: no agent WS connected for owner %s", owner)

    async def send_to_browser(self, sid: str, data: bytes):
        session = self.sessions.get(sid)
        if session:
            session.append_output(data)
            if session.browser_ws:
                try:
                    await session.browser_ws.send_bytes(data)
                except Exception:
                    logger.debug("Failed to send to browser for session %s", sid)


hub = RelayHub()
