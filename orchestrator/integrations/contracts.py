"""Validated, versioned inputs and outputs shared by integration adapters."""
from __future__ import annotations

import hashlib
import json
from typing import Literal
import re
from urllib.parse import parse_qsl, unquote_plus, urlencode, urljoin, urlsplit, urlunsplit

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


MAX_APPLICATION_COOKIES = 16


class ApplicationCookie(StrictModel):
    """A cookie that is the APPLICATION'S CONFIGURATION, not anybody's credential.

    DVWA's security level is the measured case: `dvwa/includes/dvwaPage.inc.php:200`
    returns `$_COOKIE['security']` when set and "impossible" otherwise, so the level is a
    value the CALLER chooses. An arm that omits it is not a less privileged caller — it is
    testing a different application. Measured through the real proxy against
    `/vulnerabilities/authbypass/get_user_data.php`:

        identity arm, security=low      200, 273 bytes, the full user table
        anonymous arm, no cookie at all 200,  41 bytes, {"result":"fail",...}

    and the anonymous arm is the load-bearing clause of both cross-arm authorization
    checks, so that gap MANUFACTURED a finding: measured 1 false positive on data DVWA
    publishes to anybody, and 0 once the anonymous arm carried the cookie.

    WHY THIS IS SAFE TO ADD, which is the whole reason it is separate from `Identity`:
    it is applied to EVERY arm — each identity stage, the anonymous stage, and the
    liveness control request. Anything every arm carries cannot distinguish one arm from
    another, so it can only ever LOSE a finding, never invent one. An operator who
    mistakenly puts a session cookie here authenticates every arm identically and sees
    findings disappear — and `service.authenticate`'s differential then refuses the
    identity outright, because its check stops discriminating.
    """
    name: str = Field(min_length=1, max_length=200)
    value: str = Field(max_length=4096)
    # REQUIRED, and the whole origin — scheme, host AND port. `Identity.target_origin`
    # exists so per-arm material cannot cross origins, and the first draft of this model
    # reused the same cookie plumbing with that fence removed: measured, a cookie declared
    # for localhost:8081 was put on a request to localhost:3000, and no `domain` value
    # could scope it to one origin (`domain: "localhost:8081"` silently matched nothing,
    # because a cookie domain has no port). Juice Shop treats a bare `token` cookie as a
    # full identity, so on a two-host scope that handed a credential to a second
    # application.
    target_origin: str
    path: str = Field(default="/", max_length=500)

    @model_validator(mode="after")
    def sane(self):
        origin = urlsplit(self.target_origin)
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username:
            raise ValueError("application cookie requires an HTTP(S) target origin")
        if origin.path not in ("", "/") or origin.query or origin.fragment:
            raise ValueError("target_origin must not contain a path, query, or fragment")
        for field in ("name", "value", "target_origin"):
            text = getattr(self, field)
            # A `;` or a newline would let one declared cookie become two, or smuggle a
            # header. The proxy serialises these into a single `cookie:` line.
            if any(c in text for c in ";\r\n\x00"):
                raise ValueError(f"cookie {field} must not contain ';' or a control character")
        if "=" in self.name or any(c.isspace() for c in self.name):
            raise ValueError("cookie name must not contain '=' or whitespace")
        if not self.path.startswith("/"):
            raise ValueError("cookie path must start with '/'")
        return self


# Declared objects, bounded. An identity naming a thousand of them is a configuration
# mistake rather than a matrix.
MAX_DECLARED_OBJECTS = 200


class Identity(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    target_origin: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[dict] = Field(default_factory=list)
    storage_state: dict | None = None
    check: RequestSpec

    # THE MATRIX (E-008). All four are OPERATOR-DECLARED and none is a secret, which is
    # the whole point: the `ownership` evaluator rests on who the caller IS coming from
    # the operator while the asserted owner comes from the target, so a target can cost
    # itself a finding and cannot manufacture one.
    #
    # `subject_id` was previously passed per-run in the target dict. That works for a
    # hand-driven check and cannot work in the lane, where authentication happens at the
    # PROXY and a case carries no credentials — so nothing told a case who it was running
    # as. On the identity it travels with the ARM rather than the run, and two arms cannot
    # share one by accident.
    #
    # `role` and `tenant` are labels the operator chooses; the lane does not interpret
    # them, it reports them, so "cross-tenant" becomes something a reader can see rather
    # than infer.
    role: str = Field(default="", max_length=80)
    tenant: str = Field(default="", max_length=80)
    subject_id: str = Field(default="", max_length=200)
    may_access: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid(self):
        origin = urlsplit(self.target_origin)
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username:
            raise ValueError("identity requires an HTTP(S) target origin")
        if origin.path not in ("", "/") or origin.query or origin.fragment:
            raise ValueError("target_origin must not contain a path, query, or fragment")
        if self.check.method.upper() != "GET":
            raise ValueError("authentication check must use GET")
        # AN AUTHENTICATION CHECK MUST ASSERT A SUCCESS.
        #
        # Two measured reasons, both about what a non-2xx assertion can actually establish.
        # (1) A rejection never proves a credential works, and the target controls which
        #     rejection it sends: Juice Shop answers `/api/Users` 401 "Invalid token: no
        #     header in signature" to a GARBAGE bearer token and 401 "No Authorization
        #     header was found" to no token at all. An assertion keyed on the former passes
        #     both the check AND the anonymous differential while the target is explicitly
        #     rejecting the material — the target supplying the discriminator.
        # (2) A 3xx assertion is unreachable anyway. The worker follows redirects, so a
        #     live DVWA session asserting 302 on /index.php is reported 200 and the arm is
        #     failed as dead.
        if not 200 <= self.check.expected_status < 300:
            raise ValueError(
                "authentication check must expect a 2xx: a non-2xx response cannot "
                "establish that a credential works, and the worker follows redirects so a "
                "3xx is never observed")
        if canonical_origin(self.check.url) != canonical_origin(self.target_origin):
            raise ValueError("authentication check must share the identity origin")
        for key, value in self.headers.items():
            if key.lower() in ("host", "connection", "proxy-authorization", "content-length"):
                raise ValueError("transport headers cannot be authentication headers")
            if any(c in key + value for c in "\r\n"):
                raise ValueError("invalid header")
        # The declarations reach a command template and an evidence quote, so they are
        # held to the rule every other declared field is held to.
        from orchestrator.engagement import looks_injectable
        for field in ("role", "tenant", "subject_id"):
            value = getattr(self, field)
            if value and looks_injectable(value):
                raise ValueError(f"{field} {looks_injectable(value)}")
        if len(self.may_access) > MAX_DECLARED_OBJECTS:
            raise ValueError(f"at most {MAX_DECLARED_OBJECTS} declared objects per identity")
        for item in self.may_access:
            # A PATH, never a URL. A declaration that can name a host lets an identity
            # claim access to a different machine, and nothing downstream would catch it
            # — the same reasoning `declared.PATH_FIELDS` already applies.
            if not isinstance(item, str) or not item.startswith("/") or item.startswith("//"):
                raise ValueError("each declared object must be a path on the target, "
                                 "beginning with a single '/'")
            if looks_injectable(item) or ".." in item:
                raise ValueError("a declared object must be a plain path")
        return self


def identity_target_fields(identity) -> dict[str, str]:
    """The identity's DECLARATIONS, as target fields a case may interpolate.

    In the assessment lane a case carries no credentials — the egress proxy injects the
    identity's headers and cookies on every in-scope request — so nothing told a case who
    it was running as, and the `ownership` evaluator's `subject_id` could only be supplied
    by hand. That made a working evaluator unreachable from a real assessment, which is the
    same unwired shape E-027 found in the `idor` evaluator.

    Only the non-secret declarations travel. A case that needs credentials is meant to be
    REFUSED by the lane (`inventory.IDENTITY_FIELDS`), not quietly handed them in a target
    field, and an empty declaration is omitted rather than passed as "" — the evaluator's
    question "is an owner asserted for this caller" must not look answered when nobody
    said who the caller is.
    """
    identity = identity or {}
    out = {}
    for field, name in (("subject_id", "subject_id"), ("role", "identity_role"),
                        ("tenant", "identity_tenant")):
        value = str(identity.get(field) or "").strip()
        if value:
            out[name] = value
    return out


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
    """One operator assertion: "this identity must not be able to see this string here."

    IT RESTS ON ONE ARM AND ONE RESPONSE. There is no second identity and no anonymous
    control, so unlike the cross-arm checks it cannot tell a privilege crossing from
    published content — the operator's declaration is the whole of the claim. Two ways it
    was measured producing a HIGH finding from nothing are refused by the validator below;
    a third, an operator naming a marker that a catch-all route happens to serve (Juice
    Shop answers `/administration` with index.html, which contains "Juice Shop"), is not
    detectable from one response and is why `basis` says what this rests on.
    """
    request: RequestSpec
    identity_id: str
    description: str = Field(min_length=1)
    forbidden_marker: str = Field(min_length=1)

    @model_validator(mode="after")
    def the_marker_is_not_our_own_input(self):
        # THE TARGET MUST NOT BE ABLE TO SATISFY THIS BY ECHOING THE REQUEST. Measured:
        # `GET /rest/track-order/ERLIK-PRIVATE-ORDER-4711` answers 200 with a 68-byte body
        # containing that id, because the whole record is the value from the path — and this
        # assertion then emitted a HIGH `confirmed` Broken Access Control finding. Same gate,
        # same reason, as the reflection clause in `cross_arm_privileged_function`.
        marker = self.forbidden_marker.strip()
        if marker and (marker in self.request.url or marker in unquote_plus(self.request.url)):
            raise ValueError(
                "forbidden_marker appears in the request URL, so the target can satisfy "
                "this assertion by echoing the request back; name a string the application "
                "stores rather than one this probe supplies")
        return self


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
    # Injected on EVERY arm, including the anonymous one and the liveness control. See
    # ApplicationCookie for why that is what makes it safe.
    application_cookies: list[ApplicationCookie] = Field(default_factory=list)
    # An UNAUTHENTICATED arm alongside the identity arms. Default True because without one
    # the lane's authorization work does not function at all: both cross-arm checks require
    # an anonymous arm, `register` created one only when NO identity was configured, and so
    # on every assessment the product actually accepts they refused with
    # `anonymous_arm_did_not_run`. Measured on a two-identity registration: 4 stages, 2
    # arms, no anonymous one — the three-arm sessions their tests exercise were written into
    # the database by the tests themselves.
    #
    # It is also the clause that PREVENTS false positives rather than producing findings:
    # it is what distinguishes a privilege crossing from published content. It costs one
    # more pass of each selected stage, which is the price of the comparison meaning
    # anything.
    anonymous_arm: bool = True
    # One plain GET of each discovered endpoint, per arm, as the evidence the cross-arm
    # authorization checks compare. Default True, and inert on a single-arm assessment:
    # there is nothing to difference, so the requests would buy nothing. See
    # deterministic.SURFACE_READ for why the checks were a capability with no input without
    # it, and why it is not a catalogue case.
    surface_read: bool = True
    # Derive object INSTANCE urls from the collection bodies the surface read captures, and
    # read those too. Object-level authorization lives on instances while the lane discovers
    # collections: measured on a real run, `/api/Users` had endpoint rows and `/api/Users/1`
    # had none, and enabling this took the privileged-function check from 1 of 4 known
    # violations to 2 with no false positives.
    #
    # OFF BY DEFAULT, and the reason is measured rather than cautious. The surface read can
    # say every URL it fetches was already fetched by this arm's own crawler, so it changes
    # the VOLUME of requests and not the class of side effect. A derived instance cannot say
    # that, and on the project's own primary lab app the first derived reads land on writes:
    # `GET /rest/memories/1` and `GET /rest/products/search/1` both answer 500, Juice Shop's
    # `errorHandlingChallenge` fires on `statusCode > 401`, and `challengeUtils.solve` runs
    # `challenge.save()` — a database write, plus an outbound webhook when one is configured.
    # `GET /rest/basket/:id` writes for any id that is not the arm's own basket.
    #
    # So this is an operator's decision, not a default. It additionally requires `active`.
    derive_instances: bool = False
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
        if len(self.application_cookies) > MAX_APPLICATION_COOKIES:
            raise ValueError(f"at most {MAX_APPLICATION_COOKIES} application cookies")
        pairs = [(cookie.target_origin, cookie.name) for cookie in self.application_cookies]
        if len(pairs) != len(set(pairs)):
            # Two values for one name at one origin is not configuration, it is a coin
            # toss: the proxy would send one of them and the arms would agree only by luck.
            raise ValueError("duplicate application cookie name for one target_origin")
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
    testable, companions, submit_name = [], [], None
    for control in form.get("controls") or []:
        name = (control.get("name") or "").strip()
        if not name or not PARAMETER_NAME.match(name):
            continue
        if (control.get("type") or "") in TESTABLE_CONTROLS:
            if name not in testable:
                testable.append(name)
        else:
            if (control.get("type") or "") == "submit" and submit_name is None:
                submit_name = name
            companions.append((name, str(control.get("value") or "")))
    if not testable:
        return None
    parts = urlsplit(action)
    # urlencode, because a companion VALUE is target-controlled text going into
    # a URL. The form's own query is dropped: `action` may repeat what the
    # controls already say, and the controls are the authoritative version.
    #
    # BOUNDED BY WHOLE PAIRS, never by characters. This was
    # `urlencode(companions)[:MAX_COMPANION_QUERY]`, which cut the last pair
    # mid-value: with one 700-byte hidden field (ASP.NET's __VIEWSTATE is
    # routinely kilobytes) the probe carried a PARTIAL value the application never
    # emitted, and the submit control — the entire reason companions are in the
    # URL at all — fell off the end. Two arms differing only in that value kept
    # different fragments, so they forked as well.
    #
    # The submit control goes first, because it is the one the handler needs: a
    # probe that reaches nothing is worse than a probe missing a hidden field.
    # Anything that does not fit is dropped WHOLE. A request the lane did not
    # intend to make is the defect being avoided here, and it is the same reason a
    # parameter name containing `#` is refused outright.
    ordered = sorted(companions, key=lambda pair: pair[0] != submit_name)
    kept, used = [], 0
    for name, value in ordered:
        encoded = urlencode([(name, value)])
        # +1 for the "&" this pair needs once it is not the first.
        cost = len(encoded) + (1 if kept else 0)
        if used + cost > MAX_COMPANION_QUERY:
            continue
        kept.append((name, value))
        used += cost
    # Back into the order the form declared them, so the URL still reads like the
    # form it came from.
    order = {name: index for index, (name, _) in enumerate(companions)}
    query = urlencode(sorted(kept, key=lambda pair: order[pair[0]]))
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    # SORTED before the cap. `testable[:MAX_FORM_PARAMETERS]` was DOM order, so a
    # control the target renders first in one arm — DVWA's csrf form puts
    # `password_current` first at `impossible` — pushed a different control off the
    # end, and the two arms disagreed about a parameter for a reason that has
    # nothing to do with the application. Sorting makes the kept set depend on the
    # NAMES, which both arms agree about.
    return url, sorted(testable)[:MAX_FORM_PARAMETERS]


# An inferred route is the only endpoint the lane learns from a BODY rather than from
# a request it watched, so both bounds are deliberately tight.
MAX_INFERRED = 40
MAX_INFERRED_PATH = 120

# A path, then a query parameter name. Anchored on a single leading slash: a
# protocol-relative `//host/...` is a different ORIGIN wearing a path's clothes, and
# resolving one against the target silently leaves the target.
_ROUTE = re.compile(
    r"(?<![A-Za-z0-9_/:.])/(?!/)"            # one slash, not two, not mid-token
    r"([A-Za-z0-9_./-]{1," + str(MAX_INFERRED_PATH) + r"})"   # the path
    # `#` is INCLUDED so a fragment is seen rather than silently cut around. A query
    # captured up to a `#` would hand back `a` from `?ok=1&a#b=2` — a name the
    # application never had, and the same truncation the parameter rules already
    # refuse for `a#b`. Seen, then refused below.
    r"\?([A-Za-z0-9_%=&.#\-]{1,200})")


# The same shape written relative to the document, which is how Juice Shop's bundle
# spells its open redirect: `url:"./redirect?to=https://..."`. Resolvable only when the
# caller says which script the body came from — see the `base` argument.
_RELATIVE_ROUTE = re.compile(
    r"(?<![A-Za-z0-9_/:.])\./([A-Za-z0-9_./-]{1," + str(MAX_INFERRED_PATH) + r"})"
    r"\?([A-Za-z0-9_%=&.#\-]{1,200})")


def infer_endpoints(body: str, limit: int = MAX_INFERRED,
                    base: str = "") -> list[tuple[str, list[str]]]:
    """Routes a JavaScript body names, as (path, parameter names).

    Discovery is the lane's binding constraint and this is the measured reason. On
    Juice Shop it reports 136 endpoints, 4 parameters and 2 informational findings,
    while the application's error-based SQL injection sits behind an Angular XHR that
    no crawler follows — and the route is in `main.js`, a file the lane already
    fetches:

        .get(`${this.hostServer}/rest/products/search?q=${e}`)

    Handed that URL directly the lane reports the injection HIGH in 21 seconds. So the
    parameter was one body extractor away from the inventory, which is what E-007 means
    by an operation "inferred from JavaScript/schema".

    EVERYTHING THIS RETURNS IS TARGET-CONTROLLED TEXT on its way to becoming a URL the
    lane requests and a parameter name it injects into, so the refusals are the
    substance of the function:

      - one leading slash, never two. `//w.soundcloud.com/player/?url=` is in the same
        bundle and resolves to a DIFFERENT HOST; the scope check would refuse the
        request, but only after the candidate had been counted as surface.
      - no scheme, no `..`, and only `[A-Za-z0-9_./-]` in the path, so a `${id}`
        placeholder cannot be mistaken for a segment and nothing can open the argv.
      - parameter names must satisfy PARAMETER_NAME, the same rule a discovered query
        string is held to.
      - a path with NO parameter is not returned: the parameter is the whole value, and
        an unobserved path is the riskiest thing to request.

    What it deliberately does NOT do is decide that any of this is safe to probe.
    Measured from the same ten candidates, `/rest/products/search?q=` and
    `/rest/user/change-password?current=` are syntactically indistinguishable, and the
    second is a real mutating endpoint. Callers treat these as proposals — see
    `inventory.seeds` and `inventory.parameters_by_url`, which withhold them.
    """
    candidates = [(m.group(1), m.group(2), False) for m in _ROUTE.finditer(body or "")]
    if base:
        # A relative route is meaningless without the document it was written in, and
        # meaningful with it: `./redirect?to=` inside `/main.js` is `/redirect`, which
        # is what a browser would resolve it to. Refused entirely when the caller
        # cannot say where the body came from, because the alternative is a guess.
        candidates += [(m.group(1), m.group(2), True)
                       for m in _RELATIVE_ROUTE.finditer(body or "")]

    found: dict[str, list[str]] = {}
    for path, query, relative in candidates:
        if ".." in path or "://" in path:
            continue
        if relative:
            resolved = urlsplit(urljoin(base, "./" + path))
            # urljoin cannot leave the origin from a `./` path, but the check is cheap
            # and the consequence of being wrong is a request to another host.
            if canonical_origin(base) != canonical_origin(urljoin(base, "./" + path)):
                continue
            path = (resolved.path or "/").lstrip("/")
        # A fragment means the query was not a query. `?ok=1&a#b=2` truncated to
        # `ok=1&a` yields the name `a`, which the application never had — exactly the
        # silent truncation the parameter-name rule refuses elsewhere. Refuse the
        # candidate rather than keep the part before the cut.
        if "#" in query:
            continue
        path = "/" + path
        names = [name for name in parameter_names("http://x" + path + "?" + query)
                 if PARAMETER_NAME.match(name)]
        if not names:
            continue
        from orchestrator.engagement import looks_injectable
        if looks_injectable(path):
            continue
        bucket = found.setdefault(path, [])
        for name in names:
            if name not in bucket:
                bucket.append(name)
        if len(found) >= limit:
            break
    return [(path, sorted(names)) for path, names in sorted(found.items())]


def operation_key(url: str, method: str = "GET", parameters=()) -> str:
    """What makes two observations the same OPERATION.

    E-007 asks for an inventory of operations with concrete URLs as observations
    beneath them, and E-008 requires that "two identities testing the same
    operation must produce the same operation set". Those two are the same
    requirement seen from different ends, and this function is where they meet.

    An operation is identified by **what can be injected into it**, not by what
    rides along to reach the handler:

        origin + path + method + the testable parameter names

    The companion query is deliberately absent. Measured on DVWA, same session,
    only the `security` cookie changed:

        low         controls: id (text), Submit (submit)
        impossible  controls: id (text), Submit (submit), user_token (hidden)

    `form_endpoint` puts companion NAME=VALUE pairs into the URL, so the hardened
    arm's URL carries a token DVWA regenerates on every observation of the page.
    Keying on the URL string made one form into two operations, the two arms
    shared one of eight (url, parameter) pairs, and the differential compared two
    surfaces instead of one variable.

    Keying on companion NAMES would not have fixed it either: the hardened arm
    genuinely has an extra field. Keying on the testable set does, because that
    set is `id` in both arms — which is the honest answer, since `id` is the
    input either arm would inject.

    WHAT THIS MUST NOT MERGE, and why each is kept:
      - methods, because a POST form's controls are body parameters and probing
        them as query parameters invents a location;
      - origins and paths, for the obvious reason;
      - different testable sets, because two forms on one path with different
        injectable inputs are two operations and merging them would hide one;
      - identities and tenants, which are NOT part of this key at all — they key
        the observation. Two identities observing one operation is the entire
        point; merging their findings is not.

    The cost is accepted deliberately: two forms differing only in a hidden field
    the target varies — `?mode=simple` against `?mode=advanced` — become one
    operation with two observations. Nothing is lost, because every distinct
    companion set is kept on the observations beneath it, and execution can use
    whichever actually reaches the handler. Today those are two unrelated rows
    with no stated relationship at all.

    A target cannot choose this key. It is computed from the path the target
    served and the input NAMES on its own form — never from a value, which is the
    part a target rotates, and the part that forged the divergence.
    """
    parts = urlsplit(url)
    origin = canonical_origin(url)
    path = parts.path or "/"
    # Sorted and de-duplicated: discovery order is not a property of the
    # operation, and two arms need not enumerate a form's inputs in one order.
    names = ",".join(sorted({str(name) for name in parameters if str(name)}))
    return f"{method.upper()} {origin}{path} [{names}]"


class Endpoint(StrictModel):
    url: str
    method: str = "GET"
    source: str
    identity: str = "anonymous"
    # Names observed ON this endpoint, so a case never tests a parameter
    # against a URL it was not seen on.
    parameters: list[str] = Field(default_factory=list)


# HOW MUCH TARGET-CONTROLLED TEXT A FINDING MAY QUOTE.
#
# It lived as three separate copies of `1500`, in `adapters`, `interactsh` and
# `deterministic`, and a fourth was about to be written for the cross-arm path.
# It belongs next to the field it bounds: every producer now imports it from
# here, and the three modules re-export it so existing importers still resolve.
MAX_EVIDENCE_CHARS = 1500


class IntegrationFinding(StrictModel):
    fingerprint: str
    title: str
    url: str
    rule: str
    source: str
    method: str = "GET"
    parameter: str = ""
    identity: str = "anonymous"
    # THE OTHER ARM, when the claim is a comparison between two of them.
    #
    # `identity` alone cannot carry a differential claim: a privileged-function
    # finding says "this arm reached something it should not have", and "should
    # not have" is only meaningful relative to the arm it was compared against.
    # Recording half of an ordered pair also made the pair unverifiable — nothing
    # could notice that a session held the SAME comparison asserted in both
    # directions, which is how a swapped declaration produced four confirmed rows
    # for two violations with the roles inverted on two of them.
    #
    # Empty for every single-arm finding, which is all of the catalogue ones.
    compared_with: str = ""
    # WHICH OPERATOR DECLARATIONS THIS RESTS ON, as keyed labels — never as text.
    #
    # A LIST, because two declarations about one operation are two proofs of ONE
    # vulnerability, not two vulnerabilities. `fingerprint` has no marker term, so two
    # markers against one URL build one key; the records then collided and
    # `INSERT OR REPLACE` kept only the second digest, which is how a row came to attest
    # to the last declaration alone while its own comment claimed the digest existed "so
    # two markers used in one session can be told apart". Merged by `persist_findings`
    # the way `evidence_ids` is.
    #
    # NOT in the `evidence` prose, which is the reason this is a field at all: the prose
    # is built before the merge happens, so a digest written into it could never reflect
    # what the merge produced. Rendered into the export from here instead.
    marker_digests: list[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: Literal["suspected", "likely", "confirmed"] = "suspected"
    # WHY THE CLAIM WAS MADE — lane-authored, and safe to render as-is.
    basis: str
    # WHAT THE APPLICATION ACTUALLY SENT — the bytes the claim rests on.
    #
    # These are two different things and they used to be one. `basis` said
    # "regex evaluator matched captured tool output" and the proof never left the
    # process: the blind evaluators build a byte-level comparison (control sizes,
    # then the first differing window quoting `User ID is MISSING` against `User
    # ID exists`) and it reached the evidence blob and stopped there. Measured on
    # 2026-09-10: a client reading a HIGH-severity SQL injection got one sentence
    # and a list of ids.
    #
    # It stays SEPARATE from basis because its provenance is different. This is
    # target-controlled text — an application chooses what it puts here — so
    # every consumer has to treat it as data: redacted on the way in, bounded,
    # and never interpolated anywhere it could be read as markup. basis never
    # needs that care and evidence always does.
    evidence: str = ""
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
