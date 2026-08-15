"""Tests for PoC re-verification.

Three defects are pinned here.

UNREACHABLE CLASS. poc_reverify_session reads only the "curl" key out of
_HARD_CONFIRMATION_PATTERNS, and "command injection" had only a "commix" entry —
so a critical Command Injection finding collected zero signatures and could never
be confirmed, in the class where confirmation matters most.

MATCH-EVERYTHING. vuln_type is nullable, and the class matcher
`gt_type in vt or vt in gt_type` is true for every class when vt is the empty
string. An untyped finding was therefore tested against the union of all
signatures, where loose tokens like /302/ or /redirect/ match nearly any HTTP
response — manufacturing a confirmation out of nothing.

CONFIRM-ONLY. The routine only ever set verified = 1. A finding that failed
re-verification was indistinguishable from one never tested, so verified = 0
carried no information.

The fix records poc_status (confirmed | not_reproduced | untested). Note what it
deliberately does NOT do: mark false_positive. The re-check is a plain GET of the
finding's URL, so anything needing a POST, auth, a payload parameter, or a blind
technique fails to reproduce for reasons that say nothing about the finding.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.main as main_mod

ID_OUTPUT = "HTTP/1.1 200 OK\n\nuid=0(root) gid=0(root) groups=0(root)"
BLAND = "HTTP/1.1 302 Found\nLocation: http://juice-shop:3000/#/\nX-Powered-By: Express\n\nredirect"


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    asyncio.run(db_mod.init_db())
    return tmp_path


class _Curl:
    """Records every command execute_tool is asked to run, and replays a canned
    response body."""

    def __init__(self):
        self.commands: list[str] = []
        self.body = ""

    def respond_with(self, text: str) -> None:
        self.body = text

    def __len__(self):
        return len(self.commands)

    def __eq__(self, other):           # lets tests assert `curl_calls == []`
        return self.commands == other


@pytest.fixture
def curl_calls(monkeypatch):
    """Stub execute_tool so no real command runs."""
    rec = _Curl()

    async def fake_execute_tool(cmd, *a, **kw):
        rec.commands.append(cmd)
        return {"output": rec.body, "success": True}

    monkeypatch.setattr(main_mod, "execute_tool", fake_execute_tool)
    return rec


def _add_finding(vuln_type, severity="critical", url="http://juice-shop:3000/x"):
    async def go():
        db = await db_mod.get_db()
        try:
            await db.execute(
                "INSERT INTO sessions (id, target_url) VALUES (?, ?)",
                ("s1", "http://juice-shop:3000"))
        except Exception:
            pass
        cur = await db.execute(
            "INSERT INTO findings (session_id, vuln_type, severity, url, evidence) "
            "VALUES (?, ?, ?, ?, ?)",
            ("s1", vuln_type, severity, url, "original evidence"))
        await db.commit()
        fid = cur.lastrowid
        await db.close()
        return fid
    return asyncio.run(go())


def _row(fid):
    async def go():
        db = await db_mod.get_db()
        cur = await db.execute(
            "SELECT verified, false_positive, poc_status, evidence FROM findings WHERE id = ?",
            (fid,))
        r = await cur.fetchone()
        await db.close()
        return dict(r)
    return asyncio.run(go())


def _run():
    return asyncio.run(main_mod.poc_reverify_session(
        "s1", "http://juice-shop:3000", ["curl"], force=True))


# --- the unreachable class ------------------------------------------------

def test_command_injection_can_now_be_confirmed(temp_db, curl_calls):
    """Previously collected zero signatures and could never be verified."""
    fid = _add_finding("command injection")
    curl_calls.respond_with(ID_OUTPUT)
    assert _run() == 1
    row = _row(fid)
    assert row["verified"] == 1
    assert row["poc_status"] == "confirmed"
    assert "PoC re-verified" in row["evidence"]


def test_command_injection_is_not_confirmed_by_a_bland_response(temp_db, curl_calls):
    """The new signatures must be specific — a false RCE confirmation is worse
    than none."""
    fid = _add_finding("command injection")
    curl_calls.respond_with(BLAND)
    assert _run() == 0
    assert _row(fid)["poc_status"] == "not_reproduced"
    assert _row(fid)["verified"] == 0


# --- signature specificity -------------------------------------------------
#
# A false confirmation on an RCE finding is worse than no confirmation, so the
# command-injection signatures are pinned in both directions.

CMD_SIGS = main_mod._HARD_CONFIRMATION_PATTERNS["command injection"]["curl"]


def _first_match(body):
    import re
    return next((s for s in CMD_SIGS if re.search(s, body.lower(), re.IGNORECASE)), None)


@pytest.mark.parametrize("name, body", [
    ("id",     "HTTP/1.1 200 OK\n\nuid=0(root) gid=0(root) groups=0(root)"),
    ("passwd", "HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash"),
    ("uname",  "HTTP/1.1 200 OK\n\nLinux box 5.15.0-generic #1 SMP"),
    ("ping",   "HTTP/1.1 200 OK\n\nPING example.com (93.184.216.34) 56(84) bytes"),
    ("ls",     "HTTP/1.1 200 OK\n\ndrwxr-xr-x 2 root root 4096 Jan 1 app"),
])
def test_command_output_is_detected(name, body):
    assert _first_match(body), name


@pytest.mark.parametrize("name, body", [
    ("juice_shop_root", "HTTP/1.1 200 OK\nX-Powered-By: Express\n\n"
                        "<!DOCTYPE html><title>OWASP Juice Shop</title><app-root></app-root>"),
    ("redirect",        "HTTP/1.1 302 Found\nLocation: http://juice-shop:3000/#/\n\nredirect"),
    ("json_api",        'HTTP/1.1 200 OK\n\n{"data":[{"email":"admin@juice-sh.op","role":"admin"}]}'),
    ("stack_trace",     "HTTP/1.1 500\n\nError: SQLITE_ERROR near \"SELECT\" at /app/routes/search.js:42"),
    ("prose_with_words", "HTTP/1.1 200 OK\n\nOur Linux 5 guide explains uid and gid for root users."),
])
def test_benign_responses_do_not_confirm_rce(name, body):
    assert _first_match(body) is None, f"{name} falsely matched {_first_match(body)!r}"


def test_passwd_signature_is_multiline_anchored():
    """Regression: a bare ^ anchors to the start of the whole HTTP response, which
    begins 'HTTP/1.1 ...', so the /etc/passwd signature could never fire."""
    body = "HTTP/1.1 200 OK\nServer: nginx\n\nroot:x:0:0:root:/root:/bin/bash"
    assert _first_match(body) is not None


# --- the match-everything bug ---------------------------------------------

def test_untyped_finding_is_not_tested_against_every_signature(temp_db, curl_calls):
    """An empty vuln_type used to match every class, so this bland response —
    which contains '302', 'redirect' and 'x-powered-by' — falsely confirmed."""
    fid = _add_finding(None)
    curl_calls.respond_with(BLAND)
    assert _run() == 0
    row = _row(fid)
    assert row["verified"] == 0
    assert row["poc_status"] == "untested"


def test_untyped_finding_costs_no_request(temp_db, curl_calls):
    """With no signatures there is nothing to match, so don't spend the fetch."""
    _add_finding("")
    _run()
    assert curl_calls == []


def test_unknown_class_is_untested_not_failed(temp_db, curl_calls):
    fid = _add_finding("quantum entanglement flaw")
    curl_calls.respond_with(BLAND)
    _run()
    assert _row(fid)["poc_status"] == "untested"


# --- confirm-only ---------------------------------------------------------

def test_failure_is_recorded_distinctly_from_never_tested(temp_db, curl_calls):
    """The core defect: these two states used to be identical (verified = 0)."""
    failed = _add_finding("sql injection")
    untested = _add_finding(None)
    curl_calls.respond_with(BLAND)
    _run()
    assert _row(failed)["poc_status"] == "not_reproduced"
    assert _row(untested)["poc_status"] == "untested"
    assert _row(failed)["verified"] == _row(untested)["verified"] == 0


def test_non_reproduction_never_marks_a_false_positive(temp_db, curl_calls):
    """A plain GET failing is not proof the finding is false."""
    fid = _add_finding("sql injection")
    curl_calls.respond_with(BLAND)
    _run()
    row = _row(fid)
    assert row["poc_status"] == "not_reproduced"
    assert row["false_positive"] == 0
    assert "not a false-positive verdict" in row["evidence"]


# --- gating ---------------------------------------------------------------

def test_disabled_by_default_does_nothing(temp_db, curl_calls):
    fid = _add_finding("sql injection")
    assert asyncio.run(main_mod.poc_reverify_session(
        "s1", "http://juice-shop:3000", ["curl"], force=False)) == 0
    assert _row(fid)["poc_status"] is None
    assert curl_calls == []


def test_skipped_when_curl_is_not_enabled(temp_db, curl_calls):
    _add_finding("sql injection")
    assert asyncio.run(main_mod.poc_reverify_session(
        "s1", "http://juice-shop:3000", ["nmap"], force=True)) == 0
    assert curl_calls == []


def test_only_high_and_critical_are_examined(temp_db, curl_calls):
    low = _add_finding("sql injection", severity="low")
    high = _add_finding("sql injection", severity="high")
    curl_calls.respond_with(BLAND)
    _run()
    assert _row(low)["poc_status"] is None
    assert _row(high)["poc_status"] == "not_reproduced"


def test_findings_without_a_usable_url_are_skipped(temp_db, curl_calls):
    fid = _add_finding("sql injection", url="")
    _run()
    assert _row(fid)["poc_status"] is None
    assert curl_calls == []


def test_never_raises_when_the_store_is_broken(monkeypatch, tmp_path, curl_calls):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "nope" / "x.db")
    assert asyncio.run(main_mod.poc_reverify_session(
        "s1", "http://juice-shop:3000", ["curl"], force=True)) == 0
