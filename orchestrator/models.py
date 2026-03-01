from enum import Enum
from pydantic import BaseModel
from typing import Optional


class ScopeMode(str, Enum):
    full = "full"
    recon_only = "recon_only"
    web_vulns = "web_vulns"
    injection = "injection"
    auth_bypass = "auth_bypass"


class SessionCreate(BaseModel):
    target_url: str
    scope_mode: ScopeMode = ScopeMode.full


class SessionResponse(BaseModel):
    id: str
    target_url: str
    scope_mode: str
    status: str
    created_at: str


class StepLog(BaseModel):
    model_config = {"protected_namespaces": ()}

    id: int
    session_id: str
    phase: Optional[str] = None
    step_number: Optional[int] = None
    prompt_sent: Optional[str] = None
    model_response: Optional[str] = None
    tool_called: Optional[str] = None
    tool_input: Optional[str] = None
    tool_output: Optional[str] = None
    duration_ms: Optional[int] = None
    created_at: str


class Finding(BaseModel):
    id: int
    session_id: str
    vuln_type: Optional[str] = None
    severity: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    verified: bool = False
    false_positive: bool = False
    created_at: str
