"""Existing catalogue evaluators, executed only in the assessment sandbox."""
import json
import shlex
import time
import re
from urllib.parse import urlsplit, quote_plus
from orchestrator import http_capture
from orchestrator.testcase.runner import run_test_case
from orchestrator.testcase.schema import TestCase, TestStep
from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.scope import ScopeViolation, check_url
from .adapters import BaseAdapter, record
from .contracts import (Endpoint, StageResult, IntegrationFinding, fingerprint,
                        identity_target_fields)
from .egress_policy import EgressPolicy
from .inventory import (indistinct_urls, seeds, eligible_test_cases, form_urls, parameters_by_url,
                        case_needs_parameter, parameter_can_forge)
from .runtime import JobOutput
from .security import redact, safe_evidence

# A finding's evidence is target-controlled text that travels into a report and
# into a client's issue tracker. The runner already caps it; this is the bound on
# the other side of the seam.
MAX_EVIDENCE_CHARS = 1500
from . import persistence as db


# Options that take no value. A bundle like `-sI` decomposes into these.
# `-I` and `-G` also carry meaning beyond "present", recorded in the value.
_VALUELESS = {
    "-s": None, "--silent": None,
    "-S": None, "--show-error": None,
    "-i": None, "--include": None,
    "-L": None, "--location": None,
    "-g": None, "--globoff": None,
    "-I": "HEAD", "--head": "HEAD",
    "-G": "QUERY", "--get": "QUERY",
}

# -w/--write-out IS DELIBERATELY ABSENT. Its output is indistinguishable from
# the response in step_result.output — with `-o /dev/null` it IS the whole of
# it — so every evaluator then reads a string the case chose. Closing it needs
# more than refusing `@file` and `%output{}`: `-w "root:x:0:0:"` fires AUTHZ-01,
# INPV-07 and INPV-19 at once, and even a no-literals grammar is reopened by any
# variable that echoes case-supplied text (`%{referer}` returns -e verbatim;
# `%{url_effective}` returns a path the case, or a target's discovered link,
# chose). No case that runs in this lane uses -w at all — measured by ablation,
# it buys zero cases — so the whole class is removed rather than fenced. If
# ATHN-01 or AUTHZ-05 ever become runnable, -w returns with its output LABELLED
# so an evaluator can tell it from a response.

# Options that consume the following token.
_VALUED = {
    "-X", "--request", "-H", "--header",
    "--data", "-d", "--data-binary", "--data-urlencode",
    "-b", "--cookie", "-A", "--user-agent",
    "-o", "--output", "-D", "--dump-header",
    "-m", "--max-time", "--connect-timeout", "--max-redirs",
}

# An option whose value renders empty was never filled in (see the note in
# curl_request); dropping it is what the operator meant.
_DROP_IF_EMPTY = {"-H", "--header", "-b", "--cookie", "-A", "--user-agent"}

# `-o`/`-D` are file writes in general. These two values are the exceptions,
# and only these two: `-` is curl's own spelling of stdout, and /dev/null
# discards. /dev/stdout and /dev/stderr are NOT here — they are paths that
# resolve to /proc/self/fd/N, curl opens the target with fopen(..., "wb"), and
# on any fd backed by a regular file that TRUNCATES it. Allowing /dev/stdout
# while refusing /proc/self/fd/1 was the same permission spelled two ways, one
# granted and one denied.
_STREAM_SINKS = {"-", "/dev/null"}

# Letters that may appear in a bundle like `-sI`. Deliberately NOT _VALUELESS:
# "takes no value" is not the safety property (curl's -O takes none and writes
# a file, -k takes none and drops certificate checks), so reusing that table
# would silently widen bundling the day a harmless-looking flag is added to it.
_BUNDLABLE = {"-s", "-S", "-i", "-L", "-g", "-I", "-G"}

_NUMERIC = re.compile(r"\d+(?:\.\d+)?\Z")

# A header value curl will emit verbatim. Printable ASCII only.
_HEADER_VALUE = re.compile(r"[\x20-\x7e]*\Z")


# RFC 9110 method token. curl does NOT validate -X: it writes the string
# straight into the request line, so a value containing CRLF emits a COMPLETE
# extra request ahead of the real one --
#     -X 'GET / HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET'
# put `GET / HTTP/1.1 / X-Injected: yes` on the wire before the request curl
# meant to send. Verified against the pinned curl with a raw socket server.
# The mutation gate happens to refuse a mangled method (it is not GET/HEAD/
# OPTIONS, so it needs an operation route, and no route matches it either) --
# but "the smuggling is stopped by a check that was looking for something
# else" is not a defence, it is a coincidence.
_METHOD = re.compile(r"[A-Za-z]{1,20}\Z")


def _urlencode_segment(value: str) -> str:
    """Reproduce one --data-urlencode item the way curl builds it.

    curl reads the item as `name=content`, `=content`, `content`, `@file` or
    `name@file`, deciding on whichever of `=` or `@` comes FIRST. The file
    forms are refused by the caller; the rest are rebuilt here so the URL this
    parser returns is the URL curl will request.

    Escapes are lowercased because curl emits `%3d` where Python emits `%3D`.
    RFC 3986 makes those equivalent, so nothing downstream would MISBEHAVE on
    the difference — but the returned URL is supposed to BE the request, and a
    string that merely means the same thing is a weaker claim than one that
    matches. Verified byte-for-byte against the pinned curl.
    """
    name, sep, content = value.partition("=")
    if not sep:
        encoded = quote_plus(value)
    elif not name:
        encoded = quote_plus(content)
    else:
        encoded = name + "=" + quote_plus(content)
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), encoded)


def curl_request(command):
    """Parse a deliberately small argv dialect; never pass catalogue text to a shell.

    The (url, method) returned here is what the scope check and the
    state-changing gate are decided on, so the parser's whole job is to refuse
    anything that would let the REQUEST differ from what it reports — and to
    refuse anything that reads or writes a local file, carries its own
    credentials, or leaves the proxy.

    GLOBBING IS OFF, ALWAYS. curl expands `[1-100]` and `{a,b}` in a URL into
    many requests, and `http://{a,b}.test/` into requests to DIFFERENT HOSTS —
    all from a single argv token, so "exactly one explicit HTTP destination"
    was not true of the request, only of the text. Discovered endpoints are
    substituted into these commands verbatim, so a target that serves a link
    containing `[` chose the fan-out. `-g` is emitted unconditionally (its
    position does not matter to curl) and a case may also pass it harmlessly.
    """
    try:
        args = shlex.split(command)
    except ValueError as exc:
        # An unbalanced quote, usually because a target-supplied value carried
        # one. run_test_case only catches ScopeViolation, so letting ValueError
        # out of here failed the whole STAGE instead of refusing one step.
        raise ScopeViolation(f"command does not tokenise: {exc}") from exc
    if not args or args.pop(0) != "curl":
        raise ScopeViolation("unsupported deterministic execution tool")
    method, urls, headers, data = "GET", [], [], False
    follows_redirects = False
    # -I and -X are SEPARATE state in curl: -I sets no-body, -X replaces the
    # verb. Tracking them in one variable made the parser report whichever came
    # last, so `-X DELETE -I` reported HEAD while curl put `DELETE /u/7` on the
    # wire — verified. Kept apart, and the combination refused.
    custom_method, head_only = None, False
    query_from_data, query_parts = False, []
    # argv is REBUILT from what was validated, never echoed back raw, so an
    # option this parser decided to drop cannot reach the sandbox anyway.
    emitted: list[str] = ["-g"]
    i = 0
    while i < len(args):
        arg = args[i]

        # A bundle of value-less short flags (`-sI`). A bundled option that
        # TAKES a value is refused rather than decomposed, because curl hands
        # it the rest of the bundle and then reads the next token as a URL:
        # `-As ua https://app.test` is `-A s` plus TWO destinations, which is
        # how a bundle would smuggle a second host past the check below.
        if len(arg) > 2 and arg[0] == "-" and arg[1] != "-" and arg not in _VALUELESS:
            letters = ["-" + c for c in arg[1:]]
            if any(f not in _BUNDLABLE for f in letters):
                raise ScopeViolation("unsupported bundled curl options")
            args[i:i + 1] = letters
            continue

        if arg in _VALUELESS:
            marker = _VALUELESS[arg]
            if arg in ("-L", "--location"):
                follows_redirects = True
            if marker == "HEAD":
                head_only = True
            elif marker == "QUERY":
                # -G moves the data into the query string, so a GET carrying
                # data is legitimate here and the URL below has to be rebuilt.
                query_from_data = True
            if arg not in ("-g", "--globoff"):
                emitted.append(arg)

        elif arg in _VALUED:
            i += 1
            if i == len(args):
                raise ScopeViolation("missing curl option value")
            value = args[i]
            # A catalogue case written for the legacy lane carries
            # `-b "{{cookie}}" -H "{{auth_header}}"`. In an assessment those
            # target fields do not exist — identity is attached by the proxy,
            # per stage — so they render to the empty string. An empty option
            # is not a request to send nothing in particular; it is an option
            # that was never filled in, and dropping it is what the operator
            # meant. Refusing it instead made every auth-capable case in the
            # catalogue unrunnable here.
            if value == "" and arg in _DROP_IF_EMPTY:
                i += 1
                continue

            if arg in ("-X", "--request"):
                if not _METHOD.match(value):
                    raise ScopeViolation("a request method is a bare token")
                custom_method = value.upper()

            elif arg in ("-H", "--header"):
                # The allowlist is about what a header can REPOINT or IMPERSONATE.
                # These five describe the request the browser would have made;
                # none of them changes the destination (that is Host, refused)
                # and none carries identity (that is Cookie/Authorization, also
                # refused). The two Access-Control-Request-* headers are what a
                # CORS preflight IS — without them WSTG-CLNT-07b could state a
                # preflight in YAML and never send one.
                if value.split(":", 1)[0].lower() not in (
                        "origin", "accept", "content-type",
                        "access-control-request-method", "access-control-request-headers",
                ) or any(c in value for c in "\r\n"):
                    raise ScopeViolation("unsupported catalogue header")
                headers.append(value)

            elif arg in ("-b", "--cookie"):
                # A NON-empty cookie would be the case authenticating itself,
                # behind the back of the stage's identity. The lane's isolation
                # guarantee — one identity per stage, applied by the proxy — is
                # only worth anything if a case cannot opt out of it.
                raise ScopeViolation(
                    "catalogue requests cannot carry their own credentials; "
                    "identity is applied per stage by the assessment proxy")

            elif arg in ("-A", "--user-agent"):
                # -A becomes a request header, and curl emits the value into
                # the header block without validating it: a CR or an LF (either
                # alone is enough) appends arbitrary extra headers. Verified on
                # curl 7.88.1 and 8.14.1 — `-A 'ua\r\nCookie: sid=stolen'` puts
                # that Cookie on the wire, which is the case authenticating
                # itself on a stage that was given no identity.
                #
                # -e/--referer shared this branch and was removed: it appears
                # nowhere in the catalogue, so it was arbitrary-header-value
                # surface bought for no case at all. This whole branch now
                # exists for one hardcoded "Mozilla/5.0" in WSTG-INFO-03.
                #
                # This is the ONLY gate: the proxy inspects host, port, method
                # and Upgrade, never arbitrary request headers. Printable ASCII
                # rather than just a CR/LF ban, because no catalogue value needs
                # more and a header value was never meant to carry control
                # characters.
                if not _HEADER_VALUE.match(value):
                    raise ScopeViolation("unsupported catalogue header")

            elif arg in ("-o", "--output", "-D", "--dump-header"):
                if value not in _STREAM_SINKS:
                    raise ScopeViolation(
                        "catalogue requests may only write to a stream "
                        "(" + ", ".join(sorted(_STREAM_SINKS)) + ")")

            elif arg == "--max-redirs":
                # Integers only (curl exits 2 on `--max-redirs 3.5`, which the
                # decimal-tolerant numeric check would have passed through) and
                # never above curl's own default of 50, so a case can only
                # NARROW what plain -L already permits. Measured on the pinned
                # curl: `--max-redirs 999999999` against a self-redirect loop
                # issued 2310 requests from one argv token. Every hop IS
                # policed by the proxy, so this is not a scope hole — it is
                # target-chosen volume charged to the request budget, and each
                # hop is attributed in the finding to the URL the case named
                # rather than the one actually fetched.
                if not re.fullmatch(r"[0-9]{1,2}", value) or not 0 < int(value) <= 50:
                    raise ScopeViolation("--max-redirs takes a whole number of hops, at most 50")

            elif arg in ("-m", "--max-time", "--connect-timeout"):
                # Bounds only, and the sandbox appends its own --max-time after
                # this argv — curl takes the LAST occurrence, so a case cannot
                # widen the stage budget, only narrow it.
                if not _NUMERIC.match(value) or float(value) <= 0:
                    # `-m 0` is curl's spelling of "no timeout" — the opposite
                    # of a bound. It is neutralised today only because the
                    # sandbox appends its own --max-time afterwards and curl is
                    # last-wins; that ordering is a real guarantee, but a case
                    # asking for no timeout should be refused on its own terms.
                    raise ScopeViolation("curl limit options take a positive number")

            elif arg == "--data-urlencode":
                # curl reads `@file` and `name@file` by whichever of `=` or `@`
                # comes first. Both read a local file AND put its contents in
                # the query string, which is a read primitive and an exfil
                # channel in one; the plain `--data` check (`startswith("@")`)
                # does not see the `name@file` spelling.
                at, eq = value.find("@"), value.find("=")
                if at != -1 and (eq == -1 or at < eq):
                    raise ScopeViolation("catalogue requests cannot read local files")
                data = True
                query_parts.append(_urlencode_segment(value))

            else:  # --data / -d / --data-binary
                if value.startswith("@"):
                    raise ScopeViolation("catalogue requests cannot read local files")
                data = True
                query_parts.append(value)

            emitted.extend([arg, value])

        elif urlsplit(arg).scheme in ("http", "https"):
            # Userinfo is a credential, and a case may not carry one — the same
            # rule as -b, which it would otherwise sidestep by spelling the
            # cookie into the URL. EgressPolicy refuses this too ("invalid HTTP
            # destination"), but a refusal that names the reason belongs where
            # the other credential rule already lives.
            if urlsplit(arg).username or urlsplit(arg).password:
                raise ScopeViolation(
                    "catalogue requests cannot carry their own credentials; "
                    "identity is applied per stage by the assessment proxy")
            urls.append(arg)
            emitted.append(arg)

        else:
            raise ScopeViolation("unsupported curl option or execution syntax")
        i += 1

    if head_only and custom_method and custom_method != "HEAD":
        raise ScopeViolation(
            "-I and -X state two different methods; curl would send the -X verb")
    method = custom_method or ("HEAD" if head_only else "GET")

    # A body is refused by what it IS, not by which verb was declared. The old
    # guard only fired for GET, so `-X HEAD -d "id=7&confirm=true"` slipped
    # past: curl sends HEAD with a Content-Length and the body, and the proxy
    # sees HEAD and permits it — an arbitrary form-encoded payload delivered to
    # an in-scope URL on a stage that reports itself read-only, with nothing in
    # the audit log to show a body existed. Verified on the wire.
    if data and not query_from_data and method in ("GET", "HEAD", "OPTIONS"):
        raise ScopeViolation("a body-carrying request is not a safe method")

    # -L HANDS THE TARGET THE NEXT DESTINATION, AND -X SURVIVES THE HOP.
    # curl keeps CURLOPT_CUSTOMREQUEST across a redirect — there is no 302
    # POST->GET downgrade — so `-L -X DELETE /users/999` against a target that
    # answers `302 Location: /users/1` puts `DELETE /users/1` on the wire.
    # Verified. Both gates approve that: the parser reports /users/999,
    # step_policy and EgressPolicy approve DELETE for it, and when the operator
    # selected an OpenAPI operation like DELETE /users/{id} the route's
    # `/users/[^/]+` regex fullmatches the redirected path too — so the proxy
    # permits it and attaches the stage identity, because the origin still
    # matches. The target chose which resource was deleted and nothing refused
    # it. mitmproxy gives the addon no redirect provenance, so there is no
    # proxy-side fix; the combination has to be refused here.
    #
    # A SAFE method may still follow redirects (WSTG-INFO-03 does): every hop
    # is re-checked by the proxy for host, port, path and method, so the worst
    # case is a request to some other in-scope URL, not a mutation.
    if follows_redirects and method not in ("GET", "HEAD", "OPTIONS"):
        raise ScopeViolation(
            "a state-changing request may not follow redirects; the target "
            "would choose which resource it acts on")
    if len(urls) != 1:
        raise ScopeViolation("expected one explicit HTTP destination and method")

    url = urls[0]
    if query_from_data and query_parts:
        # Mirror what curl will actually request: the data is appended to the
        # query, joined to an existing one with `&`. The proxy re-checks the
        # real URL, so this reconstruction is for an honest pre-flight
        # decision, not the only place the destination is policed.
        url += ("&" if urlsplit(url).query else "?") + "&".join(query_parts)
    return ["curl", *emitted], url, method


def target_budget(max_urls: int, selected: int, steps: int) -> int:
    """How many (endpoint, parameter) pairs one selected case may test.

    NO CASE MAY STARVE ANOTHER: the URL budget is shared across the whole stage, so
    cases running in selection order meant the first broad one took all of it. Each
    selected case gets an equal share, denominated in requests — a case with four steps
    reaches a quarter as many pairs as a single-step case for the same share.

    Module-level because the launch preview answers the same question before the run, and
    two copies of one fact is the defect this codebase already names about its own
    catalogue lists. Never zero: a selected case that could test nothing at all would
    run, find nothing, and the zero would read as clean.
    """
    share = max_urls // max(1, selected)
    return max(1, share // max(1, steps))


# The reserved id of the SURFACE READ — one plain GET of each discovered endpoint, as this
# stage's identity, recorded as evidence and evaluating nothing.
#
# WHY IT EXISTS. Three increments built cross-arm authorization checks
# (`inventory.cross_arm_authorization`, `cross_arm_privileged_function`) that compare what
# each arm received for the same request. They read the evidence catalogue cases leave
# behind — and NOT ONE runnable case simply reads a discovered endpoint. Measured on the
# first real three-arm run: both checks ran clean, 34 and 37 operations compared, no
# refusals, and found nothing, because no arm had ever asked for a privileged object. The
# checks were a capability with no input.
#
# WHY IT IS NOT A WSTG CASE. It concludes nothing on its own and must not pretend to: one
# read by one identity cannot distinguish privileged data from published data, which is the
# whole reason the comparison is cross-arm. A catalogue entry whose evaluator can never fire
# is the vacuous-case shape this project keeps deleting, so this has NO evaluator and is not
# in the catalogue.
#
# It is deliberately the same id and step name on every arm, because the cross-arm checks key
# evidence on (url, test_case, step, parameter) and a comparison needs the arms to agree on
# all four.
#
# A PLAIN GET IS NOT ALWAYS A READ, and this probe does not pretend otherwise. Measured on
# Juice Shop: a bare `GET /rest/captcha/` runs `CaptchaModel.build().save()` and rotates the
# live captcha (captchaId 51 then 52 on two consecutive reads); `GET /rest/saveLoginIp`
# updates the user row; retrieving five static PNGs under `/assets/public/images/padding/`
# flips challenges to solved; and `GET /rest/web3/nftMintListen` makes the TARGET open a
# websocket to a public host. `state_changing: false` cannot express any of that, because it
# is about the METHOD and these are about the application's semantics.
#
# WHAT BOUNDS THE EXPOSURE IS WHERE THE URLS COME FROM. `seeds()` returns only this arm's own
# `integration_endpoints` rows, minus script-inferred routes (never requested by anything) and
# minus form-synthesised actions, with fragments collapsed — so every URL here was already
# REQUESTED BY THIS ARM'S OWN CRAWLER during discovery. Verified on a real run: 0 of the 86
# URLs read were absent from that arm's rows, and `/rest/captcha/` was discovered by the
# browser pass, meaning its write had already happened before this probe existed. The read
# changes the VOLUME of requests, not the class of side effect the lane already causes.
SURFACE_READ_ID = "ERLIK-SURFACE-READ"

SURFACE_READ = TestCase(
    id=SURFACE_READ_ID,
    name="Read the discovered surface as this identity",
    category="Authorization",
    steps=[TestStep(
        name="read",
        tool="curl",
        # No evaluator. The verdict is not here; it is in the cross-arm comparison, which
        # needs this arm's answer AND the other arms' answers for the same request.
        command='curl -s -i --connect-timeout 3 --max-time 8 "{{url}}"',
    )],
)


# Extensions whose responses are bytes off a disk. A static asset cannot differ by
# identity, so it cannot carry an authorization differential — and the surface read exists
# only to feed one.
_STATIC_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".bmp", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".css", ".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".gz",
    # A script bundle is never an API response. Measured: `/main.js` and `/polyfills.js`
    # took two of twelve slots on the real Juice Shop inventory.
    ".js",
)

# Conventional directories for bytes off a disk. `/assets/i18n/en.json` is static and its
# extension cannot say so, while a bare `.json` endpoint is a plausible API — so the
# directory carries this one, not the suffix list.
_STATIC_SEGMENTS = frozenset({"assets", "static", "public", "images", "img", "fonts",
                              "css", "styles", "media"})


def looks_static(url: str) -> bool:
    """Is this URL bytes off a disk rather than a response about a caller?"""
    from urllib.parse import urlsplit

    path = (urlsplit(url).path or "").lower()
    if path.endswith(_STATIC_SUFFIXES):
        return True
    return any(segment in _STATIC_SEGMENTS for segment in path.split("/"))


def surface_read_order(urls):
    """The order the surface read spends its budget in: dynamic first, static last.

    NOT A FILTER — a stable reordering, so a generous budget still reads everything and a
    tight one spends on what can actually differ between arms.

    `seeds()` returns `ORDER BY url`, i.e. alphabetical, and that wasted the share. Measured
    on a real Juice Shop inventory at `max_urls=60` with four cases, where the read's share
    is twelve: those twelve were the homepage, `MaterialIcons-Regular.woff2`, two JSON APIs,
    `favicon_js.ico`, `assets/i18n/en.json` and six product JPEGs — and the first `/rest/`
    URL sat at rank 24. The probe was precise and reached nothing, which is the same
    "bottleneck is reaching the endpoint" this project has measured before. Reordering took
    that from 3 of 12 API URLs to 10 of 12 on the same inventory.

    IT DOES NOT DEDUPE FRAGMENTS, because `seeds()` already has. A fragment is never sent to
    a server, so `/#/about` and `/#/contact` are the same request as `/` — verified on Juice
    Shop, all three answer 200 with an identical 3748 bytes — and a draft of this did collapse
    them. `inventory.seeds` runs every candidate through `urldefrag` before returning it, so
    the probe's input holds no fragment to collapse: measured on a real run, 0 of the 86 URLs
    read carried one. Code that cannot fire implies a protection that is not there.
    """
    return sorted(urls, key=lambda url: (looks_static(url), url))


def surface_read_budget(max_urls: int, cases: int) -> int:
    """How many endpoints the surface read may fetch.

    It takes ONE share, as if it were one more single-step case, so enabling it does not
    quietly halve what every catalogue case gets. It competes for the same proxy URL ceiling
    as everything else in the stage — `max_urls` bounds distinct URLs per sandbox — so
    pretending it were free would only move the truncation somewhere less visible.
    """
    return target_budget(max_urls, cases + 1, 1)


class CatalogueAdapter(BaseAdapter):
    name = "testcases"

    # Methods that read. Everything else changes something on the target, and
    # V1 of this lane does not do that — see _v1_step_policy.
    SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

    @staticmethod
    def _v1_step_policy(policy_config, step, command):
        """Refuse a catalogue step that would write to the target. V1 rule.

        docs/future-plan.md E-003: "V1 catalogue follow-up refuses all mutation
        steps, or an explicit per-case fixture/cleanup wrapper handles them; no
        leftover probe artifact in the lab."

        This used to defer to the egress policy — refusing only when the policy
        said no. But the policy governs SCOPE, and once an operator selects
        `state_changing` with a matching operation route it says yes. Measured:
        WSTG-CONF-06's put_probe then ran and wrote `erlik_put_test.txt` to the
        client's server, and nothing recorded the write or undid it.

        Nine catalogue steps use a non-safe method; two of the cases carrying
        them run in this lane. What refusing costs is stated rather than hidden,
        and pinned by tests/test_catalogue_mutations.py:

          WSTG-CONF-06  keeps its medium detection from the Allow header and
                        loses the high confirmation that writes the file.
          WSTG-INPV-07  loses EVERYTHING. All four of its steps are POST and all
                        four emit findings, so XXE is undetectable in this lane
                        until a fixture and cleanup wrapper exists (E-012).

        That is a real recall loss and it is the deliberate trade: erlik cannot
        name what a POSTed XML document created on someone's server, so it cannot
        declare the undo, so it does not make the request.
        """
        from orchestrator.integrations.egress_policy import EgressPolicy
        try:
            _, url, method = curl_request(command)
        except ScopeViolation:
            return None  # The checker reports unsupported paths as a failure.
        if method.upper() in CatalogueAdapter.SAFE_METHODS:
            return None
        permitted = EgressPolicy(policy_config).check(url, method)[0]
        return ("skipped: this step would mutate the target with " + method.upper()
                + (", which the scope policy permits, but the catalogue lane cannot "
                   "declare an undo for a write it did not define — see E-003"
                   if permitted else
                   ", and a state-changing operation was not selected"))

    async def run(self, ctx, sandbox, collector=None):
        started_at = time.monotonic()
        result = StageResult(metadata={"catalogue": [], "executed_checks": 0})
        policy = EgressPolicy(sandbox.policy)
        def check(command, scope, primary_url=None):
            _, url, method = curl_request(command)
            check_url(url, scope)
            permitted, reason = policy.check(url, method)
            if not permitted:
                raise ScopeViolation(reason)

        # The target the loop below is currently on, so step_policy can ask what
        # this step is supposed to be probing.
        current: dict = {}

        def step_policy(step, command):
            # A STEP THAT DOES NOT SET THE PARAMETER IT WAS GIVEN, on a URL that
            # exists only because a GET form was found, SUBMITS THAT FORM BLANK.
            #
            # Measured on DVWA, 2026-09-10, in a run declaring
            # state_changing: false. WSTG-CLNT-04's `common_parameter_sweep`
            # appends six GUESSED redirect names — `redirect`, `next`, `url`,
            # `returnUrl`, `dest`, `continue` — and none of the form's own. So
            # `/vulnerabilities/csrf/?Change=Change&redirect=…` reached the
            # password-change handler with `password_new` and `password_conf`
            # both undefined, NULL == NULL compared equal, and the admin
            # password became md5(""). One request, and the lane had changed the
            # target's credentials.
            #
            # The other five steps of that same case carry {{parameter}} and are
            # harmless; this is not about the case, it is about the shape.
            url, probing = current.get("url", ""), current.get("parameter")
            if url in submit_urls and probing and f"{probing}=" not in command:
                return ("skipped: this step does not set the parameter it was given, and this "
                        "URL exists only because a GET form was found — so the request would "
                        "submit that form with its fields blank, which is an action and not a "
                        "read. Measured on DVWA: it sets the admin password to md5(\"\")")
            
            # A step whose ONLY evaluator is `llm` decides nothing here: this
            # lane runs with allow_llm=False for reproducibility, and the runner
            # skips those evaluators silently. WSTG-CLNT-04's
            # `client_side_sink_review` is one — it would have issued a real
            # request, been recorded success=True/skipped=False, counted toward
            # executed_checks, and reached no verdict at all. Declining it keeps
            # the case (its other three steps are real regex arms) while saying
            # plainly that this arm did not run.
            if step.evaluators and all(ev.type == "llm" for ev in step.evaluators):
                return ("skipped: this step decides only by LLM evaluator, and the "
                        "assessment lane runs deterministically")
            try:
                _, url, method = curl_request(command)
            except ScopeViolation:
                return None  # The checker reports unsupported paths as a failure.
            return CatalogueAdapter._v1_step_policy(sandbox.policy, step, command)

        async def execute(command, **kwargs):
            argv, _, _ = curl_request(command)
            # The appended --max-time is what makes curl's last-wins ordering a
            # real bound on a case's own -m. But custom_timeout is step.timeout
            # straight from YAML, and TestStep.timeout is an unbounded
            # Optional[int] — so `timeout: 999999` had the case authoring the
            # very budget that was supposed to bound it, leaving one step free
            # to consume the whole stage. Clamped to the stage budget, which the
            # operator set and the case cannot.
            step_seconds = min(int(kwargs.get("custom_timeout") or 20),
                               ctx.config.budget.stage_seconds)
            output = await sandbox.run([*argv, "--max-time", str(max(1, step_seconds)),
                                        "--proxy", sandbox.proxy_url, "--cacert", "/input/ca.pem"])
            blocked = bool(re.search(r"(?im)^x-erlik-blocked:\s*true", output.stdout))
            if blocked:
                # The 403 body is OUR refusal reason, not the target's response,
                # and the runner evaluates whatever output it is handed. Passing
                # the proxy's own answer through would have every evaluator read
                # a document the target never sent — finding nothing in it, and
                # reporting that as a clean probe. Nothing in the catalogue
                # matches these strings today, but "no pattern happens to match
                # our own error page" is a coincidence, not a design.
                return {"success": False, "exit_code": output.code, "output":
                        "[erlik] the assessment proxy refused this request; "
                        "the target was never contacted, so there is nothing to evaluate",
                        "error": "request refused by scope policy: " + output.stdout.strip()[-200:]}
            return {"success": output.code == 0, "output": output.stdout,
                    "exit_code": output.code, "error": output.stderr or None}

        # include_form_actions=True: this is the ONE caller that needs them, and
        # it needs them in order to report the surface it will not touch. seeds()
        # withholds them by default so no other stage can fetch one — see
        # tests/test_form_action_never_reaches_a_scanner.py.
        targets = await seeds(ctx, sandbox.policy, include_form_actions=True)
        # Parameter names discovered on this identity's endpoints. A case that
        # interpolates {{parameter}} runs once per (endpoint, parameter) pair
        # and ONLY against a URL the parameter was actually observed on —
        # pairing them any other way would test a parameter somewhere it was
        # never seen, and report the result against the URL.
        parameters = await parameters_by_url(ctx, sandbox.policy)
        # A URL that exists only because a GET form was found is not a page to
        # read; requesting it performs the form's action. See
        # inventory.form_urls for the measurement — on DVWA a bare GET, HEAD or
        # OPTIONS of `/vulnerabilities/csrf/?Change=Change` sets the admin
        # password to the md5 of an empty string, while a parameter probe of the
        # same URL changes nothing. So these URLs are kept for the cases that
        # probe a PARAMETER on them and withheld from the ones that would merely
        # fetch them, which gain nothing by doing so.
        submit_urls = await form_urls(ctx)
        # NO CASE MAY STARVE ANOTHER.
        #
        # The proxy spends config.max_urls on distinct (method, URL) across the
        # whole stage, so the budget is shared. Cases ran in selection order
        # against everything they were eligible for, which meant the first
        # broad case took all of it. Measured against Juice Shop: WSTG-SESS-02
        # swept 120 discovered URLs, and 29 of the 60 parameter probes that
        # followed were refused "URL budget exhausted" — including
        # `/redirect?to=//erlik-redir.oast.test/`, the probe for that
        # application's KNOWN open redirect. The stage reported zero findings,
        # and zero meant untested rather than clean.
        #
        # Each selected case now gets an equal share, denominated in requests
        # because one target costs a case one request per step. A case with
        # fewer targets than its share simply uses less; a case with more says
        # what it did not reach.
        def case_budget(case):
            return target_budget(ctx.config.max_urls, len(ctx.config.test_cases),
                                 len(case.steps))
        result.metadata["parameters_discovered"] = sum(len(v) for v in parameters.values())
        # Empty unless the surface read ran and found repeats; the no-parameter cases below
        # consult it either way.
        indistinct: dict = {}

        # THE SURFACE READ, before the cases, because it is what the cross-arm checks
        # consume. See SURFACE_READ for why it exists and why it is not a catalogue case.
        #
        # Only when there is another arm to compare against: a single-arm assessment has
        # nothing to difference, and the requests would buy nothing. `config.identity_ids`
        # being non-empty is the same condition that registers the anonymous arm, so the
        # arms this produces evidence for are exactly the arms that exist.
        #
        # `submit_urls` is excluded by the same rule the no-parameter cases use: a URL that
        # exists only because a GET form was found is not a page, and requesting it performs
        # the form's action — measured on DVWA, a bare GET of
        # /vulnerabilities/csrf/?Change=Change sets the admin password to md5("").
        if ctx.config.identity_ids and ctx.config.surface_read:
            share = surface_read_budget(ctx.config.max_urls, len(ctx.config.test_cases))
            readable = surface_read_order(url for url in targets if url not in submit_urls)
            # THE SHARE IS SPLIT, not doubled. Derived instances can only be found by first
            # reading a collection, so the read is two passes — and a second pass that helped
            # itself to another whole share would make `max_urls` mean something other than
            # what the operator set.
            derived_share = share // 3 if ctx.config.derive_instances and ctx.config.active else 0
            reading = readable[:share - derived_share]
            read_count, reached, bodies = 0, [], []

            async def read_one(url):
                """One recorded GET as this identity. Returns the capture, or None."""
                current.clear()
                current.update({"url": url})
                target = {"url": url, "scope": ctx.config.scope.model_dump(),
                          **identity_target_fields(ctx.identity)}
                run = await run_test_case(SURFACE_READ, target, executor=execute,
                                          step_policy=step_policy, command_checker=check,
                                          allow_llm=False)
                evidence_id = await db.evidence(
                    ctx.session_id, ctx.stage_id, "testcase:" + SURFACE_READ_ID,
                    run.model_dump_json(), ctx.known)
                result.evidence_ids.append(evidence_id)
                return next((step.output for step in run.steps if step.output), None)

            for url in reading:
                if time.monotonic() > started_at + ctx.config.budget.stage_seconds * 0.85:
                    break
                body = await read_one(url)
                read_count += 1
                reached.append(url)
                if body:
                    bodies.append((url, body))
            # PASS TWO: the instances those collections named.
            #
            # The lane discovers COLLECTIONS and not INSTANCES, and object-level authorization
            # lives on instances — measured on a real run, `/api/Users` had endpoint rows and
            # `/api/Users/1` had none, and three of the four known violations were unreachable
            # for that reason alone.
            #
            # UNLIKE PASS ONE, THIS IS NOT A REQUEST THE CRAWLER ALREADY MADE. Pass one can
            # say every URL it fetches was already fetched during discovery; a derived
            # instance was not. That is an escalation, so it is tied to `active` — the
            # operator's existing declaration that this run may probe — and has its own
            # switch. `inventory.safe_object_id` is what stops the TARGET choosing the
            # request: an id is used only if it is a bounded ASCII integer or a canonical
            # UUID, and the URL is rebuilt from the collection's own scheme, netloc and path.
            derived_urls, derived_read = [], 0
            if derived_share:
                from .inventory import breadth_first, instance_urls
                # BREADTH BEFORE DEPTH. Taking every instance of one collection before
                # touching the next spends a tight budget on whichever collections sort
                # first: measured on a real run, 30 candidates against a share of 28 dropped
                # two — and they were `/api/Users/2` and `/api/Users/3`, because `/api/Users`
                # comes last alphabetically. Round-robin gives every collection its first
                # instance before any gets a second, so the interesting one is reached
                # whatever its name.
                per_collection = [
                    [instance for instance in instance_urls(url, http_capture.body(body))
                     if instance not in reached]
                    for url, body in bodies]
                candidates = breadth_first(per_collection)
                # THE ANONYMOUS ARM CANNOT DERIVE THE INSTANCES THAT MATTER, so it is given
                # the ones other arms derived.
                #
                # An arm derives from collections IT can read, and the anonymous arm is
                # refused exactly the interesting ones — measured on a clean three-arm run,
                # the only derived instances all three arms shared were of PUBLIC collections
                # (Challenges, Products, Feedbacks...), while `/api/Users/1` was derived by
                # both identity arms and by neither the anonymous one. The function-level
                # check then skipped it, because clause 3 requires the anonymous arm to have
                # ASKED — and it is right to: an anonymous arm that never requested a URL
                # proves nothing about whether that URL is public.
                #
                # So the arm whose whole job is to establish "not published" is handed the
                # URLs it must ask about. The anonymous stage is registered last, so those
                # rows exist by the time it runs. This cannot invent a finding: an anonymous
                # 2xx SUPPRESSES one, so the only thing asking can do is remove findings the
                # lane would otherwise have reported.
                if ctx.identity_id == "anonymous":
                    from .inventory import derived_urls as recorded_by_other_arms
                    mine = set(candidates)
                    others = [url for url in sorted(await recorded_by_other_arms(ctx.session_id))
                              if url not in mine and url not in reached]
                    # Theirs first: those are the ones only this arm is missing.
                    candidates = others + candidates
                derived_urls = candidates[:derived_share]
                for url in derived_urls:
                    if time.monotonic() > started_at + ctx.config.budget.stage_seconds * 0.85:
                        break
                    await read_one(url)
                    derived_read += 1
                    # Recorded as an endpoint so the cross-arm checks' `gated` intersection
                    # contains it — without a row they would skip the very URLs this exists
                    # to produce. `source` says where it came from, because a URL nothing
                    # crawled must be distinguishable from one something did.
                    result.endpoints.append(Endpoint(url=url, method="GET", source="derived",
                                                     identity=ctx.identity_id))
                result.metadata["derived_instances"] = {
                    "read": derived_read,
                    "candidates": len(candidates),
                    "share_of_url_budget": derived_share,
                    "from_collections": len({url for url, body in bodies
                                             if instance_urls(url, http_capture.body(body))}),
                }
                if len(candidates) > derived_read:
                    result.observations.append({
                        "type": "surface_read_truncated", "test_case_id": SURFACE_READ_ID,
                        "url": None, "steps": [],
                        "reason": f"{len(candidates) - derived_read} of {len(candidates)} "
                                  f"object instances named by the collections read were not "
                                  f"fetched; this pass's share of the "
                                  f"{ctx.config.max_urls} URL budget is {derived_share}"})

            # WHICH OF THESE READS WERE THE SAME RESPONSE TWICE.
            #
            # Measured on a real three-arm run: 37 of 86 surface reads returned a response the
            # lane had already seen, absorbed into THREE survivors — `/`, `/api/Feedbacks` and
            # `/api/Quantitys`. The 36-strong group is the single-page application's shell,
            # which its server returns for any route it does not know, and it included
            # `/Edge/` and `/Trident/` — browser-detection regex fragments katana mined out of
            # a JavaScript bundle. Probing those for injection cannot find anything, and
            # listing them as untested reads as work outstanding when there is none.
            #
            # ONLY THE NO-PARAMETER CASES ARE PRUNED. A parameter probe is a different request
            # from the bare read that grouped, so a URL whose base response is the shell could
            # still answer differently to `?id=1'`. Measured, no pruned URL carried a
            # discovered parameter at all — but the safety is structural rather than resting
            # on that: `parameters_by_url` pairs are never touched.
            # `keep`: URLs the lane has discovered PARAMETERS for. The parameter cases build
            # their targets from `parameters_by_url` and never consult this result, so this is
            # belt and braces — it makes the safety independent of that separation holding.
            # Measured on DVWA, the two pairs it protects: `/vulnerabilities/fi/` carries
            # `page`, whose probe reads /etc/passwd, and `/vulnerabilities/xss_r/` carries
            # `name`, whose probe reflects unencoded — and each is byte-identical to junk
            # spellings that sort first.
            indistinct = indistinct_urls(((url, capture) for url, capture in bodies),
                                         keep=set(parameters))
            if indistinct:
                result.metadata["indistinct_urls"] = {
                    "count": len(indistinct),
                    "survivors": sorted(set(indistinct.values())),
                    "establishes": ("these URLs answered with a response another URL had "
                                    "already given, so a check that reads the response has "
                                    "nothing left to find on them; parameter probes are "
                                    "unaffected"),
                }
                for url, same_as in sorted(indistinct.items()):
                    result.observations.append({
                        "type": "indistinct_url", "test_case_id": SURFACE_READ_ID,
                        "url": url, "steps": [],
                        "reason": f"answered with the same response as {same_as}"})

            # Reported in the stage's METADATA rather than as `test_case` observations,
            # because `coverage()` counts those as a check having run against an endpoint
            # and this is not a check. Calling it coverage would overstate what was tested
            # by exactly the number of URLs read.
            result.metadata["surface_read"] = {
                "urls_read": read_count,
                "urls_available": len(readable),
                "urls_withheld_as_form_actions": len(targets) - len(readable),
                "share_of_url_budget": share,
                "establishes": ("nothing on its own — it is the evidence the cross-arm "
                                "authorization checks compare, and a single read by a single "
                                "identity cannot tell privileged data from published data"),
            }
            if read_count < len(readable):
                result.observations.append({
                    "type": "surface_read_truncated", "test_case_id": SURFACE_READ_ID,
                    "url": None, "steps": [],
                    "reason": f"{len(readable) - read_count} of {len(readable)} in-scope URLs "
                              f"were not read as this identity, so the cross-arm "
                              f"authorization checks have no evidence for them; this probe's "
                              f"share of the {ctx.config.max_urls} URL budget is {share}"})

        # STOP BEFORE THE AXE FALLS. service.py wraps each stage in
        # asyncio.timeout and, on expiry, REPLACES the accumulated StageResult
        # with an empty one — so a stage that found a real vulnerability at
        # minute 3 and ran out of budget at minute 10 reported "partial" with
        # no findings at all. Measured against Juice Shop: a 120-URL inventory
        # times out here long before it finishes, because this loop is
        # cases x urls x steps and each request is its own container (0.29s
        # measured). Leaving a margin lets the adapter return what it has, and
        # say what it did not get to.
        deadline = started_at + ctx.config.budget.stage_seconds * 0.85
        for index, case_id in enumerate(ctx.config.test_cases):
            if time.monotonic() > deadline:
                remaining = ctx.config.test_cases[index:]
                result.status = "partial"
                result.reason = ("stage time budget reached with "
                                 f"{len(remaining)} of {len(ctx.config.test_cases)} selected checks unrun")
                result.observations.append({
                    "type": "test_case_not_run", "test_case_id": ",".join(remaining), "url": None, "steps": [],
                    "reason": "the stage ran out of time before these were reached; findings above are complete "
                              "for the checks that did run"})
                break
            tc = find_by_id(case_id)
            if not tc:
                raise ValueError("selected catalogue test is unavailable: " + case_id)
            if case_id == "WSTG-INPV-19" and ctx.config.callback:
                case_targets = [probe for probe in ctx.config.callback.probes]
            elif case_needs_parameter(tc):
                pairs, forgeable = [], []
                for url, names in sorted(parameters.items()):
                    if case_id not in eligible_test_cases(url, parameters=names):
                        continue
                    for name in names:
                        if parameter_can_forge(tc, name):
                            forgeable.append(name)
                        else:
                            pairs.append({"url": url, "parameter": name})
                if forgeable:
                    result.observations.append({
                        "type": "parameter_refused", "test_case_id": case_id, "url": None, "steps": [],
                        "parameters": sorted(set(forgeable)),
                        "reason": "these parameter names match this case's own evidence pattern, so an "
                                  "application that merely echoes the name would satisfy it"})
                case_targets = pairs[:case_budget(tc)]
                if len(pairs) > len(case_targets):
                    # Said out loud, because a truncated sweep that reports
                    # nothing looks exactly like a clean one.
                    result.observations.append({
                        "type": "test_case_truncated", "test_case_id": case_id, "url": None, "steps": [],
                        "reason": f"{len(pairs) - len(case_targets)} of {len(pairs)} "
                                  f"(endpoint, parameter) pairs were not tested; "
                                  f"raise max_urls to cover them (one pair costs "
                                  f"{len(tc.steps)} of the {ctx.config.max_urls} URL budget)"})
            else:
                eligible = [{"url": url} for url in targets
                            if case_id in eligible_test_cases(url)
                            and url not in submit_urls
                            and url not in indistinct]
                withheld = sorted(u for u in targets
                                  if u in submit_urls and case_id in eligible_test_cases(u))
                if withheld:
                    result.observations.append({
                        "type": "form_url_withheld", "test_case_id": case_id, "url": None, "steps": [],
                        "urls": withheld,
                        "reason": "this check reads a URL rather than probing a parameter on it, and "
                                  "these URLs exist only because a GET form was found — requesting "
                                  "one performs the form's action. Measured on DVWA: a bare GET, "
                                  "HEAD or OPTIONS of /vulnerabilities/csrf/?Change=Change sets the "
                                  "admin password to md5(\"\")"})
                case_targets = eligible[:case_budget(tc)]
                if len(eligible) > len(case_targets):
                    result.observations.append({
                        "type": "test_case_truncated", "test_case_id": case_id, "url": None, "steps": [],
                        "reason": f"{len(eligible) - len(case_targets)} of {len(eligible)} in-scope URLs "
                                  f"were not tested; this check's share of the {ctx.config.max_urls} URL "
                                  f"budget is {case_budget(tc)} targets across "
                                  f"{len(ctx.config.test_cases)} selected checks"})
            if not case_targets:
                # Selected, and nothing to run it against. Saying nothing here
                # made the case indistinguishable from one that ran and found
                # nothing — the operator picked it, so they are owed the reason.
                result.observations.append({
                    "type": "test_case_not_run", "test_case_id": case_id, "url": None, "steps": [],
                    "reason": ("no parameter was discovered on any in-scope URL, and this case "
                               "tests one" if case_needs_parameter(tc) else
                               "no in-scope URL this case can be executed against; "
                               "see inventory.executable_test_cases")})
                result.metadata["catalogue"].append(case_id)
                continue
            for position, target in enumerate(case_targets):
                current.clear()
                current.update(target)
                if time.monotonic() > deadline:
                    result.status = "partial"
                    result.reason = "stage time budget reached mid-check"
                    result.observations.append({
                        "type": "test_case_truncated", "test_case_id": case_id, "url": None, "steps": [],
                        "reason": f"{len(case_targets) - position} of {len(case_targets)} targets were not "
                                  f"reached before the stage budget ran out"})
                    break
                # The identity's DECLARATIONS, so a case knows who it is running as.
                # The material stays at the proxy; only `subject_id`, `identity_role` and
                # `identity_tenant` travel, and only when the operator declared them.
                target = {**target, "scope": ctx.config.scope.model_dump(),
                          **identity_target_fields(ctx.identity)}
                if case_id == "WSTG-INPV-19":
                    if not collector:
                        result.status, result.reason = "partial", "SSRF check incomplete: callback collector unavailable"
                        continue
                    run = await collector.run_test_case(tc, target, sandbox)
                else:
                    run = await run_test_case(tc, target, executor=execute, step_policy=step_policy,
                                              command_checker=check, allow_llm=False)
                evidence_id = await db.evidence(ctx.session_id, ctx.stage_id, "testcase:" + case_id,
                                                run.model_dump_json(), ctx.known)
                result.evidence_ids.append(evidence_id)
                result.metadata["executed_checks"] += sum(not s.skipped for s in run.steps)
                # The parameter is part of WHICH check this was. Once a case
                # runs once per (endpoint, parameter) the observations are
                # otherwise identical, and the report cannot say which input
                # was probed.
                probed = target.get("parameter") or ""
                result.observations.append({"type": "test_case", "test_case_id": case_id, "url": target["url"],
                    "parameter": probed or None,
                    "steps": [{"name": s.step, "success": s.success, "skipped": s.skipped, "error": s.error} for s in run.steps],
                    "evidence_id": evidence_id})
                for finding in run.findings:
                    rule = case_id + ":" + finding.step
                    # fingerprint() has always taken a `parameter` and never been
                    # given one. That was harmless while a case ran once per URL;
                    # running it once per parameter makes SSTI-in-`q` and
                    # SSTI-in-`lang` on the same URL hash identically, and
                    # persist_result writes findings INSERT OR REPLACE on
                    # (session_id, fingerprint) — so one silently replaced the
                    # other and the survivor named no parameter at all. The same
                    # fingerprint is DefectDojo's dedup key, so the collapse
                    # would have been exported too.
                    result.findings.append(IntegrationFinding(
                        fingerprint=fingerprint(ctx.target, rule, "GET", target["url"], probed, ctx.identity_id),
                        title=finding.vuln_type or tc.name, url=target["url"], rule=rule, source="testcase",
                        identity=ctx.identity_id, parameter=probed,
                        severity=finding.severity, confidence=finding.confidence, basis=finding.basis or "Deterministic catalogue evaluator matched the captured HTTP response",
                        # The proof, carried rather than discarded. Redacted
                        # with ctx.known because a response body is where an
                        # identity's own cookie comes back at us, and bounded
                        # again here because the field is target-controlled and
                        # the runner's cap is on the other side of a seam.
                        evidence=safe_evidence(redact(finding.evidence, ctx.known))[:MAX_EVIDENCE_CHARS],
                        methodology=[case_id], evidence_ids=[evidence_id]))
                # A CASE THAT RECEIVED NOTHING DID NOT TEST ANYTHING.
                #
                # curl exits 0 on an empty body, so a target that refuses every
                # request — a 302 to a login form, a rejected CSRF token — comes
                # back success=True with zero bytes, every evaluator matches
                # nothing, and the case reads exactly like a clean probe.
                #
                # Measured on 2026-09-10. DVWA at security=impossible puts a
                # SINGLE-USE user_token in its forms, form_endpoint bakes it into
                # the discovered URL as a companion, and it is stale by the time
                # the cases run. 156 of the 208 injection-case steps in that run
                # received zero bytes — every probe of sqli, sqli_blind, xss_r
                # and csrf — and the stage reported `completed` with no findings.
                # That zero was then read as "the hardened application is
                # clean", which is the one thing it cannot mean.
                #
                # One step with bytes is enough to say the target answered; all
                # of them empty means it did not.
                ran = [s for s in run.steps if not s.skipped]
                if ran and not any(s.output for s in ran):
                    result.observations.append({
                        "type": "test_case_unreachable", "test_case_id": case_id,
                        "url": target["url"], "parameter": probed or None, "steps": [],
                        "reason": f"all {len(ran)} executed steps received an empty response, so this "
                                  f"check tested nothing here; a zero from it is untested coverage, "
                                  f"not a clean result"})
                    result.status = "partial"
                    result.reason = "one or more catalogue checks never reached their target"
                if any(not s.success and not s.skipped for s in run.steps):
                    result.status, result.reason = "partial", "one or more catalogue checks could not complete"
            result.metadata["catalogue"].append(case_id)
        # ONE VULNERABILITY, ONE FINDING. A step that declares `subsumed_by`
        # produces the vaguer account of something another case described better;
        # drop it once that other case has actually reported on the same
        # (endpoint, parameter). Measured on 2026-09-10: every DVWA run shipped
        # WSTG-INPV-11.2's "unclassified injection" alongside WSTG-INPV-05.2's
        # "SQL Injection (error-based)" for the same request, with byte-identical
        # proof — two HIGH findings to triage, contradicting each other about
        # whether the injection was classified.
        #
        # Done at the END rather than by not running the step, so a run where the
        # more specific case was not selected, or did not fire, still reports it.
        reported = {(f.url, f.parameter, f.rule.partition(":")[0]) for f in result.findings}
        kept, subsumed = [], []
        for finding in result.findings:
            case_id, _, step_name = finding.rule.partition(":")
            case = find_by_id(case_id)
            step = next((st for st in (case.steps if case else []) if st.name == step_name), None)
            better = [other for other in (getattr(step, "subsumed_by", None) or [])
                      if (finding.url, finding.parameter, other) in reported]
            if better:
                subsumed.append((finding, better))
            else:
                kept.append(finding)
        if subsumed:
            result.findings = kept
            for finding, better in subsumed:
                result.observations.append({
                    "type": "finding_subsumed", "test_case_id": finding.rule.partition(":")[0],
                    "url": finding.url, "parameter": finding.parameter or None, "steps": [],
                    "reason": f"{', '.join(better)} reported on the same parameter and describes it "
                              f"more precisely, so this check's vaguer account of the same response "
                              f"was not reported: {finding.title}"})

        if not result.metadata["executed_checks"] and result.status == "completed":
            result.status, result.reason = "skipped", "no applicable selected checks"
        return await record(ctx, sandbox, JobOutput(0, json.dumps(redact(result.observations, ctx.known)), ""), result)
