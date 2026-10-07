"""Tests for `orchestrator/primitive_extract.py` — the read-side primitive
extractor.

These assert against the real `extract`, never a re-implementation, and they
cover the two properties the module exists to hold: header secrets are read
only from the header block (a target cannot forge a cookie by echoing it into
its body), and every candidate survives the same injection gate the
deterministic lane applies.

Realistic fixtures: a login response (Set-Cookie + bearer), a page carrying a
CSRF token three ways, and a negative response that must yield nothing.

Mutation-tested (CLAUDE.md convention 4): replacing the Set-Cookie capture
group with a non-matching literal fails
`test_login_response_yields_session_cookie_and_bearer_token`,
`test_safe_cookie_value_still_survives` and
`test_enabled_store_roundtrips_extracted_primitives` — so those three are
attributable to the cookie parse, not passing on silence.
"""

from __future__ import annotations

import pytest

from orchestrator.primitive_extract import extract
from orchestrator.session_state import KINDS, Primitive, SessionStore


# ---------------------------------------------------------------------------
# Fixtures: raw captures as a tool would hand them over.
# ---------------------------------------------------------------------------

LOGIN_RESPONSE = """HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123DEF456; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: locale=en-GB; Path=/
X-Powered-By: Express

{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiJ9.s3cr3t_Sig-nature","umail":"admin@juice-sh.op"}}"""

CSRF_PAGE = """HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html><head>
<meta name="csrf-token" content="MetaCsrf-ABC123">
</head><body>
<form method="POST" action="/account/transfer">
  <input type="hidden" name="_csrf" value="HiddenCsrf_XYZ789">
  <input type="text" name="recipient" placeholder="to">
  <input type="number" name="amount">
  <textarea name="memo"></textarea>
  <input type="submit" value="Send">
</form>
</body></html>"""

# A clean 404 — no credential, no token, no form field. Must extract nothing.
NEGATIVE_RESPONSE = """HTTP/1.1 404 Not Found
Content-Type: text/plain
Content-Length: 46

The resource you requested could not be found."""


# ---------------------------------------------------------------------------
# The three headline fixtures.
# ---------------------------------------------------------------------------

def test_login_response_yields_session_cookie_and_bearer_token():
    prims = extract(LOGIN_RESPONSE, "juice.local")
    by_kind = {}
    for p in prims:
        by_kind.setdefault(p.kind, []).append(p)

    cookies = by_kind.get("cookie", [])
    assert [c.value for c in cookies] == ["session=abc123DEF456"], (
        "the session cookie is captured as its name=value pair, attributes stripped")
    assert cookies[0].name == "session"
    assert cookies[0].source_host == "juice.local", (
        "the issuing host is recorded as the reuse boundary")

    tokens = by_kind.get("token", [])
    assert any(t.value.startswith("eyJhbGciOiJIUzI1NiJ9.") for t in tokens), (
        "the bearer JWT in the JSON body is captured as a token primitive")


def test_non_session_cookie_is_not_captured():
    """A locale cookie is not a credential. The session-name filter is what
    stops every tracking cookie becoming a primitive."""
    prims = extract(LOGIN_RESPONSE, "juice.local")
    assert not any(p.kind == "cookie" and p.name == "locale" for p in prims)


def test_csrf_page_yields_csrf_tokens_and_injection_points():
    prims = extract(CSRF_PAGE, "bank.local")
    csrf_values = {p.value for p in prims if p.kind == "csrf"}
    assert "MetaCsrf-ABC123" in csrf_values, "the <meta> CSRF token is captured"
    assert "HiddenCsrf_XYZ789" in csrf_values, "the hidden-input CSRF token is captured"

    inj = {p.value for p in prims if p.kind == "injection_point"}
    assert {"recipient", "amount", "memo"} <= inj, (
        "editable form fields are flagged as candidate injection points")
    assert "_csrf" not in inj, (
        "the CSRF hidden field is a csrf primitive, never an injection point")


def test_csrf_json_field_is_captured():
    body = ('HTTP/1.1 200 OK\nContent-Type: application/json\n\n'
            '{"ok":true,"csrfToken":"JsonCsrf-54321"}')
    prims = extract(body, "api.local")
    assert any(p.kind == "csrf" and p.value == "JsonCsrf-54321" for p in prims)


def test_negative_response_extracts_nothing():
    assert extract(NEGATIVE_RESPONSE, "x.local") == []


def test_empty_input_extracts_nothing():
    assert extract("", "x.local") == []
    assert extract(None, "x.local") == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The forgery boundary — the reason this module leans on http_capture.
# ---------------------------------------------------------------------------

def test_set_cookie_reflected_into_the_body_is_not_captured():
    """The target wrote `Set-Cookie:` into its own HTML body. It did not set a
    cookie, and reading one back would be the target asserting its own session.
    Header secrets come only from the header block."""
    capture = ("HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
               "<p>Set-Cookie: sessionid=FORGED_BY_TARGET; Path=/</p>")
    assert not any(p.kind == "cookie" for p in extract(capture, "x.local"))


def test_token_header_reflected_into_the_body_is_not_captured():
    """An `X-Subject-Token:` line typed into the body is not a header the server
    sent, so it is not a header primitive."""
    capture = ("HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
               "<pre>X-Subject-Token: forged_token_in_body</pre>")
    assert not any(p.kind == "header" for p in extract(capture, "x.local"))


def test_token_delivered_in_a_response_header_is_captured():
    """A token delivered in a framed response header (Keystone's
    `X-Subject-Token`) is a real reusable credential, captured verbatim with its
    header name so it replays as the same header."""
    capture = ("HTTP/1.1 201 Created\n"
               "X-Subject-Token: gAAAAAB-realSubjectToken_abc123\n"
               "Content-Type: application/json\n\n{}")
    headers = [p for p in extract(capture, "x.local") if p.kind == "header"]
    assert any(h.value == "gAAAAAB-realSubjectToken_abc123"
               and h.name == "X-Subject-Token" for h in headers)


# ---------------------------------------------------------------------------
# The injection gate — values are dropped, never escaped.
# ---------------------------------------------------------------------------

def test_cookie_value_with_a_shell_metacharacter_is_dropped():
    """A session cookie whose value carries a shell metacharacter is discarded,
    not quoted. It is about to become a command argument."""
    capture = ('HTTP/1.1 200 OK\n'
               'Set-Cookie: session=abc`whoami`def; Path=/\n\nbody')
    assert not any(p.kind == "cookie" for p in extract(capture, "x.local")), (
        "a cookie value containing a backtick must not survive the injection gate")


def test_safe_cookie_value_still_survives():
    """Guard the guard above: the identical fixture without the metacharacter
    IS captured, so the drop is attributable to the gate and not to the parser
    failing on the whole line."""
    capture = ('HTTP/1.1 200 OK\n'
               'Set-Cookie: session=abcSAFEdef; Path=/\n\nbody')
    assert any(p.kind == "cookie" and p.value == "session=abcSAFEdef"
               for p in extract(capture, "x.local"))


def test_injection_point_names_that_are_unsafe_are_dropped():
    capture = ('HTTP/1.1 200 OK\nContent-Type: text/html\n\n'
               '<form><input type=text name="ok_field">'
               '<input type=text name="bad$field"></form>')
    inj = {p.value for p in extract(capture, "x.local") if p.kind == "injection_point"}
    assert "ok_field" in inj
    assert "bad$field" not in inj


# ---------------------------------------------------------------------------
# The Primitive / SessionStore contract this module produces into.
# ---------------------------------------------------------------------------

def test_every_emitted_kind_is_in_the_declared_set():
    for fixture in (LOGIN_RESPONSE, CSRF_PAGE):
        for p in extract(fixture, "h"):
            assert p.kind in KINDS


def test_primitive_rejects_an_unknown_kind():
    with pytest.raises(ValueError):
        Primitive(kind="totally_made_up", value="x")


def test_store_is_off_by_default_and_holds_nothing():
    store = SessionStore()  # enabled defaults to False
    for p in extract(LOGIN_RESPONSE, "juice.local"):
        store.add(p)
    assert len(store) == 0, "a disabled store must not accumulate credentials"


def test_enabled_store_roundtrips_extracted_primitives():
    store = SessionStore(enabled=True)
    added = store.extend(extract(LOGIN_RESPONSE, "juice.local"))
    assert added >= 2
    assert store.cookies().get("session") == "abc123DEF456"
    assert any(h.startswith("Bearer ") for h in store.auth_headers().values())
    # redact() masks a captured secret wherever it is echoed back.
    assert "abc123DEF456" not in store.redact("leak: session=abc123DEF456 trailing")


def test_store_deduplicates_identical_primitives():
    store = SessionStore(enabled=True)
    store.extend(extract(LOGIN_RESPONSE, "juice.local"))
    before = len(store)
    store.extend(extract(LOGIN_RESPONSE, "juice.local"))  # same response again
    assert len(store) == before, "the same primitive seen twice is held once"
