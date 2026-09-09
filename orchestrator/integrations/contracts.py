"""Validated, versioned inputs and outputs shared by integration adapters."""
from __future__ import annotations

import hashlib
import json
from typing import Literal
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator
from orchestrator.testcase.scope import Scope, check_url


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(StrictModel):
    requests_per_second: float = Field(default=5, gt=0, le=100)
    concurrency: int = Field(default=2, ge=1, le=20)
    stage_seconds: int = Field(default=600, ge=1, le=7200)
    assessment_seconds: int = Field(default=1800, ge=1, le=28800)


class RequestSpec(StrictModel):
    url: str
    method: str = "GET"
    body: dict | None = None
    expected_status: int = Field(default=200, ge=100, le=599)
    body_contains: str | None = None


class Identity(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    target_origin: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[dict] = Field(default_factory=list)
    storage_state: dict | None = None
    check: RequestSpec

    @model_validator(mode="after")
    def valid(self):
        origin = urlsplit(self.target_origin)
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username:
            raise ValueError("identity requires an HTTP(S) target origin")
        if origin.path not in ("", "/") or origin.query or origin.fragment:
            raise ValueError("target_origin must not contain a path, query, or fragment")
        if self.check.method.upper() != "GET":
            raise ValueError("authentication check must use GET")
        if canonical_origin(self.check.url) != canonical_origin(self.target_origin):
            raise ValueError("authentication check must share the identity origin")
        for key, value in self.headers.items():
            if key.lower() in ("host", "connection", "proxy-authorization", "content-length"):
                raise ValueError("transport headers cannot be authentication headers")
            if any(c in key + value for c in "\r\n"):
                raise ValueError("invalid header")
        return self


class SchemaInput(StrictModel):
    kind: Literal["openapi", "graphql"] = "openapi"
    content: str | None = Field(default=None, max_length=5_000_000)
    url: str | None = None

    @model_validator(mode="after")
    def source(self):
        if bool(self.content) == bool(self.url):
            raise ValueError("supply exactly one schema content or URL")
        return self


class Workflow(StrictModel):
    operations: list[str] = Field(min_length=1)  # Exact OpenAPI operationIds
    fixtures: list[RequestSpec] = Field(min_length=1)
    cleanup: list[RequestSpec] = Field(min_length=1)


class SecurityAssertion(StrictModel):
    request: RequestSpec
    identity_id: str
    description: str = Field(min_length=1)
    forbidden_marker: str = Field(min_length=1)


class CallbackConfig(StrictModel):
    server: str
    secret_id: str | None = None
    grace_seconds: int = Field(default=60, ge=1, le=300)
    probes: list[dict[str, str]] = Field(default_factory=list)


class AssessmentConfig(StrictModel):
    scope: Scope
    stages: list[Literal["zap", "schemathesis", "interactsh", "katana"]] = Field(default_factory=lambda: ["zap", "katana"])
    identity_ids: list[str] = Field(default_factory=list)
    active: bool = False
    state_changing: bool = False
    budget: Budget = Field(default_factory=Budget)
    schema_input: SchemaInput | None = None
    workflow: Workflow | None = None
    security_assertions: list[SecurityAssertion] = Field(default_factory=list)
    callback: CallbackConfig | None = None
    seed: int = Field(default=1, ge=0, le=2**32 - 1)
    crawl_depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=500, ge=1, le=10000)
    headless: bool = False
    excluded_paths: list[str] = Field(default_factory=lambda: ["/logout", "/signout"])
    ai_summary: bool = False
    # Not a Literal. The set of runnable cases is a PROPERTY OF THE PARSER, and
    # a literal here was a second hand-maintained copy of it that could only
    # ever drift — it still named exactly three cases after curl_request grew
    # able to run more. See inventory.executable_test_cases; the check lives in
    # the validator below because the answer is computed, not declared.
    test_cases: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def prerequisites(self):
        if not self.scope.allow_hosts or not self.scope.allow_ports:
            raise ValueError("integration assessments require explicit allowed hosts AND ports")
        if len(self.stages) != len(set(self.stages)):
            raise ValueError("duplicate stages")
        if not self.stages:
            raise ValueError("select at least one stage")
        if len(self.test_cases) != len(set(self.test_cases)):
            raise ValueError("duplicate test cases")
        from .inventory import executable_test_cases, COLLECTOR_CASES
        runnable = set(executable_test_cases()) | set(COLLECTOR_CASES)
        unrunnable = [case for case in self.test_cases if case not in runnable]
        if unrunnable:
            raise ValueError(
                "these catalogue cases cannot be executed in an assessment: "
                + ", ".join(sorted(unrunnable))
                + " (runnable: " + ", ".join(sorted(runnable)) + ")")
        if any(case != "WSTG-SESS-02" for case in self.test_cases) and not self.active:
            raise ValueError("selected deterministic probes require active testing")
        if "WSTG-INPV-19" in self.test_cases and "interactsh" not in self.stages:
            raise ValueError("the integration SSRF test case requires the Interactsh stage")
        if self.state_changing and not self.active:
            raise ValueError("state-changing workflows require active testing")
        if "schemathesis" in self.stages and (not self.active or not self.schema_input):
            raise ValueError("Schemathesis requires active testing and a schema")
        if self.state_changing and not self.workflow:
            raise ValueError("state-changing testing requires operations, fixtures, and cleanup")
        if self.workflow and not self.state_changing:
            raise ValueError("workflow requires state_changing=true")
        if self.workflow and not self.schema_input:
            raise ValueError("workflow requires an OpenAPI schema")
        if self.workflow and self.schema_input and self.schema_input.kind != "openapi":
            raise ValueError("stateful workflows currently require OpenAPI operation IDs")
        if "interactsh" in self.stages and (not self.active or not self.callback or not self.callback.probes):
            raise ValueError("Interactsh requires active testing, a self-hosted server, and explicit probes")
        if self.callback:
            u = urlsplit(self.callback.server)
            if u.scheme != "https" or not u.hostname or u.username or u.path not in ("", "/"):
                raise ValueError("callback server must be an explicit HTTPS origin")
            for probe in self.callback.probes:
                if set(probe) != {"url", "parameter"} or not probe["parameter"]:
                    raise ValueError("each callback probe requires url and parameter")
                check_url(probe["url"], self.scope)
        if self.schema_input and self.schema_input.url:
            check_url(self.schema_input.url, self.scope)
        for assertion in self.security_assertions:
            check_url(assertion.request.url, self.scope)
            if not self.active or assertion.request.method.upper() != "GET":
                raise ValueError("security assertions require active testing and GET requests")
            if assertion.identity_id not in self.identity_ids:
                raise ValueError("assertion identity must be selected for this assessment")
        for request in (self.workflow.fixtures + self.workflow.cleanup if self.workflow else []):
            check_url(request.url, self.scope)
        return self


def canonical_origin(url: str) -> str:
    u = urlsplit(url)
    host = (u.hostname or "").lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    return f"{u.scheme.lower()}://{host}:{u.port or (443 if u.scheme == 'https' else 80)}"


def fingerprint(target: str, rule: str, method: str, url: str, parameter: str = "", identity: str = "anonymous") -> str:
    u = urlsplit(url)
    # Parameter values often contain credentials/object IDs; names define the surface.
    from urllib.parse import parse_qsl
    endpoint = canonical_origin(url) + (u.path or "/")
    query_names = sorted({key for key, _ in parse_qsl(u.query)})
    parts = [canonical_origin(target), rule, method.upper(), endpoint, query_names, parameter, identity]
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


# A QUERY PARAMETER NAME THE LANE WILL PUT IN A COMMAND.
#
# Deliberately much narrower than "not shell-injectable". A name is
# target-controlled text rendered into a command slot, and the shell-metachar
# gate is the wrong instrument for it twice over: it passes names that silently
# CORRUPT the probe, and it rejects names that were never dangerous here.
# Measured against the real templates:
#
#   a#b   ->  ?a#b=payload    the `#` opens a FRAGMENT, so the request is `?a`
#                             and the case tests a parameter it never sent
#   a&b   ->  ?a&b=payload    two parameters, neither the one under test
#   a=b   ->  ?a=b=payload    parameter `a`, value `b=payload`
#
# None of those escape anything; each makes the case report on a probe it did
# not make, which is this project's recurring defect shape. A real query
# parameter name is what is allowed, `user[id]` and `x-token` included, and a
# leading dash is excluded so a name can never read as an option if it ever
# reaches an unquoted slot.
PARAMETER_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,63}\Z")


def parameter_names(url: str, *extra: str) -> list[str]:
    """Query parameter names on `url`, plus any the scanner named, validated."""
    found = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    seen, out = set(), []
    for name in [*found, *extra]:
        name = (name or "").strip()
        if name and name not in seen and PARAMETER_NAME.match(name):
            seen.add(name)
            out.append(name)
    return out


# Control types whose value the OPERATOR would type. Everything else named on a
# form — submit buttons, hidden tokens, checkboxes — is a COMPANION: not worth
# probing, and usually required for the form's handler to run at all.
TESTABLE_CONTROLS = frozenset({"", "text", "search", "url", "email", "tel", "number",
                               "password", "textarea", "date", "datetime-local"})

# Bounds on target-controlled text that becomes part of a URL.
MAX_FORM_PARAMETERS = 10
MAX_COMPANION_QUERY = 512


def form_endpoint(form: dict, page_url: str) -> tuple[str, list[str]] | None:
    """A GET form as (url carrying its companion fields, names worth testing).

    GET only. A POST form's controls are BODY parameters, and probing them as
    query parameters is the same category error as trusting ZAP's `param` —
    the name is real, the location is invented.

    The companion query is why this is worth doing at all. DVWA's SQLi page
    answers `?id=<payload>` with nothing and `?id=<payload>&Submit=Submit` with
    the rows, so a discovery that reported `id` alone would hand every case a
    probe that cannot reach the handler — an input discovered and untestable,
    reported as tested. The submit button and hidden token ride along; the
    testable controls do not, so a case appending its own value cannot collide
    with one already in the query.
    """
    if (form.get("method") or "GET").upper() != "GET":
        return None
    action = (form.get("action") or page_url or "").strip()
    if not action or urlsplit(action).scheme not in ("http", "https"):
        return None
    testable, companions = [], []
    for control in form.get("controls") or []:
        name = (control.get("name") or "").strip()
        if not name or not PARAMETER_NAME.match(name):
            continue
        if (control.get("type") or "") in TESTABLE_CONTROLS:
            if name not in testable:
                testable.append(name)
        else:
            companions.append((name, str(control.get("value") or "")))
    if not testable:
        return None
    parts = urlsplit(action)
    # urlencode, because a companion VALUE is target-controlled text going into
    # a URL. The form's own query is dropped: `action` may repeat what the
    # controls already say, and the controls are the authoritative version.
    query = urlencode(companions)[:MAX_COMPANION_QUERY].rstrip("&")
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    return url, testable[:MAX_FORM_PARAMETERS]


class Endpoint(StrictModel):
    url: str
    method: str = "GET"
    source: str
    identity: str = "anonymous"
    # Names observed ON this endpoint, so a case never tests a parameter
    # against a URL it was not seen on.
    parameters: list[str] = Field(default_factory=list)


class IntegrationFinding(StrictModel):
    fingerprint: str
    title: str
    url: str
    rule: str
    source: str
    method: str = "GET"
    parameter: str = ""
    identity: str = "anonymous"
    severity: str = "medium"
    confidence: Literal["suspected", "likely", "confirmed"] = "suspected"
    basis: str
    evidence_ids: list[str] = Field(default_factory=list)
    cwe: str | None = None
    triage_state: Literal["open", "false_positive", "fixed"] = "open"
    triage_note: str = ""
    methodology: list[str] = Field(default_factory=list)


StageStatus = Literal["queued", "running", "needs_auth", "completed", "partial", "failed", "cancelled", "skipped"]


class StageResult(StrictModel):
    status: StageStatus = "completed"
    reason: str = ""
    exit_code: int | None = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    observations: list[dict] = Field(default_factory=list)
    findings: list[IntegrationFinding] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
