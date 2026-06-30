from enum import Enum
from pydantic import BaseModel
from typing import Optional


# Canonical tool catalogue. Referenced by SessionCreate / ChainCreate / BenchmarkCreate
# defaults AND by the TOOLSET_PRESETS dict in main.py. Single source of truth.
_DEFAULT_TOOLS: list[str] = [
    # Recon & Scanning
    "nmap", "nuclei", "nikto", "whatweb", "wafw00f", "arjun", "whois", "sslyze", "testssl",
    # Fuzzing & Discovery
    "ffuf", "gobuster", "dirb", "wfuzz",
    # Injection & Exploitation
    "sqlmap", "xsstrike", "dalfox", "commix", "crlfuzz",
    # Auth & Crypto
    "hydra", "john", "hashcat", "jwt_tool",
    # Browser & Automation
    "playwright", "pw-crawl", "zap-cli",
    # Utilities
    "curl", "netcat",
    # Capability helpers (added 2026-04-06 for RQ3-b action-space ablation)
    "login-helper", "diff-view", "interactive-pw",
]


class ScopeMode(str, Enum):
    full = "full"
    recon_only = "recon_only"
    web_vulns = "web_vulns"
    injection = "injection"
    auth_bypass = "auth_bypass"


class SessionCreate(BaseModel):
    target_url: str
    scope_mode: ScopeMode = ScopeMode.full
    system_prompt: str = ""
    model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    enabled_tools: list[str] = _DEFAULT_TOOLS
    toolset_preset: Optional[str] = None  # "core_10" | "standard_20" | "full_30" | None (custom)
    session_type: str = "cold"
    parent_session_id: Optional[str] = None
    vuln_category: Optional[str] = None
    no_timeout: bool = False  # True = truly unlimited per-tool execution time
    tool_timeout: Optional[int] = None  # manual per-tool timeout (seconds); overrides defaults
    max_turns: int = 30  # 0 = unlimited (capped at 150 for safety)
    disable_stagnation: bool = False  # benchmark opt-out for the agent-loop stagnation auto-stop
    extra_system_prompt: str = ""  # injected memory/context appended to system prompt


class SessionResponse(BaseModel):
    id: str
    target_url: str
    scope_mode: str
    system_prompt: str
    model: str
    enabled_tools: str
    status: str
    created_at: str
    session_type: str = "cold"
    parent_session_id: Optional[str] = None
    vuln_category: Optional[str] = None
    toolset_preset: Optional[str] = None
    total_duration_ms: Optional[int] = None
    total_steps: int = 0
    total_findings: int = 0


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
    # CVE enrichment (populated when ERLIK_ENRICH_CVE is set; see enrichment/nvd.py)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    created_at: str


class ReportResponse(BaseModel):
    session_id: str
    report_markdown: str
    executive_summary: Optional[str] = None
    generated_by_model: Optional[str] = None
    generation_duration_ms: Optional[int] = None
    created_at: Optional[str] = None


class SessionMetrics(BaseModel):
    """Per-session thesis data for warm vs cold comparison."""
    session_id: str
    target_url: str
    session_type: str
    vuln_category: Optional[str] = None
    parent_session_id: Optional[str] = None
    total_steps: int = 0
    total_findings: int = 0
    total_duration_ms: Optional[int] = None
    findings_by_severity: dict = {}
    findings_by_type: dict = {}
    status: str = ""
    created_at: str = ""


# --- Chain Mode Models ---

class ChainCreate(BaseModel):
    target_url: str
    scope_mode: ScopeMode = ScopeMode.full
    system_prompt: str = ""
    model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    enabled_tools: list[str] = _DEFAULT_TOOLS
    toolset_preset: Optional[str] = None
    max_turns_per_session: int = 30
    no_timeout: bool = False
    auto_progress: bool = True
    disable_stagnation: bool = False


class ChainResponse(BaseModel):
    id: str
    target_url: str
    scope_mode: str
    model: str
    current_phase: str
    current_position: int
    total_sessions: int
    status: str
    auto_progress: bool
    max_turns_per_session: int
    created_at: str
    sessions: list[dict] = []


class ChainSessionSummary(BaseModel):
    session_id: str
    chain_position: int
    chain_phase: str
    status: str
    total_steps: int = 0
    total_findings: int = 0
    total_duration_ms: Optional[int] = None


# --- Benchmark Models ---

class BenchmarkCreate(BaseModel):
    target_url: str
    target_name: str = "OWASP Juice Shop"
    max_turns: int = 30
    no_timeout: bool = True
    repeat_n: int = 1
    model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    system_prompt: str = ""
    enabled_tools: list[str] = _DEFAULT_TOOLS
    # RQ3-b: toolset_presets is a list — benchmark runner iterates across these.
    # Empty list or None = use enabled_tools as-is (legacy behaviour).
    toolset_presets: list[str] = []
    disable_stagnation: bool = False


class BenchmarkSessionResult(BaseModel):
    session_id: str
    session_type: str
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    missed_vulns: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    severity_score: float = 0.0
    findings_per_minute: float = 0.0
    findings_per_turn: float = 0.0
    tool_coverage: float = 0.0
    unique_tools_used: int = 0
    time_to_first_finding_ms: Optional[int] = None
    time_to_first_high_ms: Optional[int] = None
    total_duration_ms: Optional[int] = None
    total_steps: int = 0
    phases_covered: list[str] = []
    vuln_types_found: list[str] = []
    severity_distribution: dict = {}


class BenchmarkResponse(BaseModel):
    id: str
    target_url: str
    target_name: str
    status: str
    model: str
    max_turns: int
    cold: Optional[BenchmarkSessionResult] = None
    warm: Optional[BenchmarkSessionResult] = None
    chain: Optional[BenchmarkSessionResult] = None
    ground_truth_count: int = 0
    created_at: str
    completed_at: Optional[str] = None
