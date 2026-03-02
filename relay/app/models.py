from pydantic import BaseModel


class GoogleLoginRequest(BaseModel):
    credential: str
    nonce: str | None = None


class LoginResponse(BaseModel):
    token: str


class CreateSessionRequest(BaseModel):
    agent_type: str  # "claude", "gemini", "codex"
    command: str
    label: str = ""
    cols: int = 80
    rows: int = 24
    device_id: str = ""
    e2ee: bool = False


class SessionInfo(BaseModel):
    session_id: str
    agent_type: str
    label: str
    status: str  # "pending", "running", "exited"
    command: str


# ── Device Pairing (local mode) ──

class PairRequest(BaseModel):
    pairing_token: str
    device_name: str
    device_id: str


class PairResponse(BaseModel):
    device_secret: str


class DeviceAuthRequest(BaseModel):
    device_id: str
    timestamp: int
    hmac: str


class DeviceInfo(BaseModel):
    device_id: str
    device_name: str
    paired_at: str  # ISO 8601


class AgentDetectionResult(BaseModel):
    name: str  # "claude", "gemini", "codex"
    installed: bool
    version: str | None = None
    install_url: str = ""


# ── Playbooks ──

class PlaybookConfig(BaseModel):
    name: str
    agent_type: str
    agent_config: dict = {}
    instructions: str = ""


class CreatePlaybookRequest(BaseModel):
    name: str
    agent_type: str
    agent_config: dict = {}
    instructions: str = ""


class UpdatePlaybookRequest(BaseModel):
    name: str | None = None
    agent_type: str | None = None
    agent_config: dict | None = None
    instructions: str | None = None


class PlaybookResponse(BaseModel):
    id: str
    name: str
    agent_type: str
    agent_config: dict = {}
    instructions: str = ""
    created_at: str
    updated_at: str


# ── Credential Vault ──

class CredentialRequestCreate(BaseModel):
    credential_name: str
    reason: str
    scope: str = "read"
    ttl_seconds: int = 300
    agent_id: str = ""
    session_id: str = ""


class CredentialRequestInfo(BaseModel):
    request_id: str
    credential_name: str
    reason: str
    scope: str
    ttl_seconds: int
    agent_id: str
    session_id: str
    status: str
    created_at: float


class CredentialResponseSubmit(BaseModel):
    encrypted_credential: str = ""
    approved: bool = True


class VaultAuditResponse(BaseModel):
    request_id: str
    credential_name: str
    agent_id: str
    session_id: str
    action: str
    timestamp: float
