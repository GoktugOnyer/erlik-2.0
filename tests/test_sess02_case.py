"""WSTG-SESS-02 had one evaluator and it was an LLM.

The question it asked -- "does this Set-Cookie header lack HttpOnly, Secure or
SameSite" -- is a string test. Routing it through a model meant the case
produced NOTHING on any deployment with no model reachable. Measured
2026-09-05 against a target serving `Set-Cookie: session=abc123; Path=/`,
which is the textbook finding this case is named for:

    findings: []
    not_assessed: [fetch_headers/llm: "LLM evaluator could not run"]

Unlike CONF-07, there was no deterministic path to fall back to at all.

The parse is now in the step, and the rules are narrower than they look --
`Secure` is required only on an https target, because demanding it of a plain
http target would flag every cookie on every such site for a flag that would
stop the cookie working; and only session-shaped cookie NAMES are judged,
because a preference cookie without HttpOnly is not a session-fixation risk
and flagging it trains an operator to ignore this case.

Verified live against eight endpoints, two of them real TLS.
"""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "tests_catalog" / "wstg" / "SESS-02_cookie_attributes.yaml"


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


@pytest.fixture(scope="module")
def step(case):
    assert len(case["steps"]) == 1
    return case["steps"][0]


def _run(command: str, url: str, headers: str) -> str:
    """Execute the step's real shell with curl shimmed to emit fixed headers.

    The point of this file is that the verdict no longer needs a model, so the
    verdict logic is EXECUTED rather than re-derived. A test that reimplemented
    the parse would reproduce whatever it got wrong.
    """
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        shim = Path(d) / "curl"
        shim.write_text("#!/bin/bash\ncat <<'EOF'\n" + headers + "\nEOF\n")
        shim.chmod(0o755)
        rendered = (command.replace("{{url}}", url)
                    .replace("{{cookie}}", "").replace("{{auth_header}}", ""))
        assert rendered.startswith("bash -c ")
        env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
        r = subprocess.run(["bash", "-c", rendered[len("bash -c "):].strip("'")],
                           capture_output=True, text=True, env=env)
        return r.stdout


def _verdict(out: str) -> str:
    v = [l for l in out.splitlines() if l.startswith("ERLIK_COOKIE")]
    assert v, out[:400]
    return v[0].split(":")[0]


OK_HEAD = "HTTP/1.1 200 OK"


class TestTheVerdictDoesNotNeedAModel:
    def test_a_regex_evaluator_can_emit_the_finding(self, step):
        emitting = [ev for ev in step["evaluators"]
                    if ev["type"] == "regex" and ev.get("emit_finding")]
        assert emitting, (
            "every finding path goes through an LLM, so the case is inert on "
            "any run with no model reachable"
        )

    def test_the_llm_is_a_second_opinion_not_the_only_one(self, step):
        llm = [ev for ev in step["evaluators"] if ev["type"] == "llm"]
        for ev in llm:
            assert ev.get("when") == "no_finding_yet", (
                "the model must not be asked what the parse already answered"
            )


class TestTheParseIsRight:
    @pytest.mark.parametrize("scheme,cookie,expected", [
        # No flags at all -- the case this exists for.
        ("http", "session=abc123; Path=/", "ERLIK_COOKIE_INSECURE"),
        # Complete for a cleartext target: Secure would stop it working.
        ("http", "session=abc; Path=/; HttpOnly; SameSite=Lax", "ERLIK_COOKIE_OK"),
        # Over TLS, Secure IS required.
        ("https", "sessionid=abc; HttpOnly; SameSite=Lax", "ERLIK_COOKIE_INSECURE"),
        ("https", "sessionid=abc; HttpOnly; SameSite=Lax; Secure", "ERLIK_COOKIE_OK"),
        # Missing one attribute each.
        ("http", "session=abc; SameSite=Lax", "ERLIK_COOKIE_INSECURE"),
        ("http", "session=abc; HttpOnly", "ERLIK_COOKIE_INSECURE"),
        # Other session-shaped names.
        ("http", "PHPSESSID=abc; Path=/", "ERLIK_COOKIE_INSECURE"),
        ("http", "csrf_token=abc; Path=/", "ERLIK_COOKIE_INSECURE"),
        ("http", "auth=abc; Path=/", "ERLIK_COOKIE_INSECURE"),
        # NOT session-shaped: flagging these is noise that gets the case
        # ignored.
        ("http", "theme=dark; Path=/", "ERLIK_COOKIE_OK"),
        ("http", "_ga=GA1.2.99; Path=/", "ERLIK_COOKIE_OK"),
    ])
    def test_one_cookie(self, step, scheme, cookie, expected):
        out = _run(step["command"], f"{scheme}://127.0.0.1:9030/",
                   f"{OK_HEAD}\nSet-Cookie: {cookie}\nHTTPCODE=200")
        assert _verdict(out) == expected, out[-300:]

    def test_a_flagged_and_an_unflagged_cookie_together(self, step):
        """The mixed case: one good session cookie must not excuse a bad one."""
        out = _run(step["command"], "http://127.0.0.1:9030/",
                   f"{OK_HEAD}\nSet-Cookie: sid=1; HttpOnly; SameSite=Lax\n"
                   "Set-Cookie: token=2; Path=/\nHTTPCODE=200")
        assert _verdict(out) == "ERLIK_COOKIE_INSECURE"
        assert "token" in out

    def test_the_offending_cookie_and_attribute_are_named(self, step):
        """A finding an operator cannot act on is half a finding."""
        out = _run(step["command"], "http://127.0.0.1:9030/",
                   f"{OK_HEAD}\nSet-Cookie: session=abc123; Path=/\nHTTPCODE=200")
        line = [l for l in out.splitlines() if l.startswith("ERLIK_COOKIE")][0]
        assert "session" in line
        assert "HttpOnly" in line and "SameSite" in line

    def test_secure_is_not_matched_inside_another_word(self, step):
        """`grep -qi secure` would match a cookie NAMED `insecure_pref` or a
        `Path=/secure` attribute, and call a flagless cookie compliant."""
        out = _run(step["command"], "https://127.0.0.1:9030/",
                   f"{OK_HEAD}\nSet-Cookie: session=abc; Path=/secure; "
                   "HttpOnly; SameSite=Lax\nHTTPCODE=200")
        assert _verdict(out) == "ERLIK_COOKIE_INSECURE", out[-300:]


class TestTheHonestNonVerdicts:
    def test_no_cookies_is_not_a_finding(self, step):
        out = _run(step["command"], "http://127.0.0.1:9032/",
                   f"{OK_HEAD}\nHTTPCODE=200")
        assert _verdict(out) == "ERLIK_COOKIE_NONE_SET"

    def test_no_response_is_not_a_finding(self, step):
        out = _run(step["command"], "http://127.0.0.1:9099/", "HTTPCODE=000")
        assert _verdict(out) == "ERLIK_COOKIE_NO_RESPONSE"

    def test_no_response_renders_as_not_assessed(self):
        ui = (ROOT / "dashboard" / "templates" / "index.html").read_text()
        rx = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", ui).group(1)
        assert re.search(rx, "ERLIK_COOKIE_NO_RESPONSE")
        assert not re.search(rx, "ERLIK_COOKIE_INSECURE")
        assert not re.search(rx, "ERLIK_COOKIE_OK")

    @pytest.mark.parametrize("verdict,expected", [
        ("ERLIK_COOKIE_INSECURE", 1),
        ("ERLIK_COOKIE_OK", 0),
        ("ERLIK_COOKIE_NONE_SET", 0),
        ("ERLIK_COOKIE_NO_RESPONSE", 0),
    ])
    def test_each_verdict_fires_the_right_evaluators(self, step, verdict, expected):
        hits = [ev for ev in step["evaluators"] if ev["type"] == "regex"
                and re.search(ev["pattern"], f"{verdict}: detail")]
        assert len(hits) == expected, [ev["pattern"] for ev in hits]


class TestTheBodyCannotBeMistakenForAHeader:
    def test_headers_only(self, step):
        """`-i` includes the body, so a page containing the text
        `Set-Cookie:` would be parsed as one. `-D - -o /dev/null` cannot."""
        # Checked on the CURL invocation, not the whole command -- the parse
        # itself uses `grep -i`, and asserting over the string caught that.
        curls = re.findall(r'curl\s+-[^;|)]*', step["command"])
        assert curls, step["command"]
        for c in curls:
            assert " -i " not in c and not c.endswith(" -i"), c
            assert "-D -" in c and "-o /dev/null" in c, c
