"""The export-boundary redactor.

`review.redact_secrets` reused `primitives._PATTERNS` — an EXTRACTOR's
patterns, which describe how a secret looks in a RESPONSE. But
`primitives.inject_credentials` writes secrets into REQUESTS. Measured against
the live function before this change: 11 of the 20 templates in
`primitives._AUTH_FLAGS` leaked the secret verbatim, every cookie form among
them. The lever that manufactures the leak and the redactor meant to catch it
were describing different halves of the same exchange.

Positive controls are generated FROM `_AUTH_FLAGS`, so adding a tool there
without a matching pattern fails this suite rather than silently leaking.
Negative controls run over the whole recorded corpus plus the specific benign
literals the corpus happens not to contain.
"""

import sqlite3
from pathlib import Path

import pytest

from orchestrator.redaction import mask, census, mask_url, PLACEHOLDER_RX
from orchestrator.primitives import _AUTH_FLAGS

JWT_A = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.AAAAAAAAAAAA"
JWT_B = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjJ9.BBBBBBBBBBBB"
COOKIE = "session=abc123def456ghi789"
SECRETS = {"bearer": JWT_A, "cookie": COOKIE}

FLAG_CASES = [(tool, kind, tpl)
              for tool, flags in sorted(_AUTH_FLAGS.items())
              for kind, tpl in sorted(flags.items())]


class TestEveryInjectedCredentialIsMasked:
    @pytest.mark.parametrize("tool,kind,tpl", FLAG_CASES,
                             ids=[f"{t}-{k}" for t, k, _ in FLAG_CASES])
    def test_auth_flag_template_does_not_survive(self, tool, kind, tpl):
        """Generated from _AUTH_FLAGS: a new tool with no matching pattern fails
        here instead of leaking in production."""
        secret = SECRETS[kind]
        cmd = f"{tool} {tpl.format(v=secret)} http://juice-shop:3000/"
        out = mask(cmd)
        assert secret not in out, f"{tool}/{kind} leaked: {out}"
        assert PLACEHOLDER_RX.search(out), f"{tool}/{kind} produced no placeholder"

    @pytest.mark.parametrize("text", [
        'nikto -id "admin:hunter2pass" -h http://t',
        "JWT weak secret cracked: s3cr3tkey123",
        'curl -b "session=abc123def456ghi" http://t/x',
    ])
    def test_headline_leaks_are_closed(self, text):
        assert mask(text) != text


class TestDistinctness:
    def test_two_different_jwts_do_not_collapse(self):
        """A constant placeholder merges two distinct commands during dedup —
        a real defect, not a cosmetic one."""
        assert mask(JWT_A) != mask(JWT_B)

    def test_same_secret_masks_identically(self):
        assert mask(f"a {JWT_A}") .split()[1] == mask(f"b {JWT_A}").split()[1]

    def test_placeholder_carries_no_secret_prefix(self):
        """Digest, not prefix: the first characters of a session cookie are
        usually the cookie NAME."""
        out = mask(f'curl -b "{COOKIE}" http://t/')
        assert "session" not in out
        assert "abc123" not in out


class TestIdempotence:
    @pytest.mark.parametrize("text", [
        "Set-Cookie: sid=abc123def456",
        f'curl -H "Authorization: Bearer {JWT_A}" http://t/',
        'nikto -id "admin:hunter2pass" -h http://t',
    ])
    def test_masking_twice_is_stable(self, text):
        """Overlap-based, not equality-based: on `Set-Cookie: sid=abc` the
        response rule fires and the `Cookie:` rule then matches the RESULT in
        the same pass, starting INSIDE the placeholder."""
        once = mask(text)
        assert mask(once) == once


class TestCensusCountsDistinctSecrets:
    def test_one_jwt_in_a_token_field_counts_once(self):
        """The `jwt` pattern fires, then the `token` pattern re-matches the
        placeholder. Naive counting reports two secrets of the wrong kinds."""
        c = census(f'{{"token": "{JWT_A}"}}')
        assert sum(c.values()) == 1, c

    def test_two_distinct_secrets_count_twice(self):
        c = census(f'{JWT_A} and {JWT_B}')
        assert sum(c.values()) == 2, c

    def test_same_secret_twice_counts_once(self):
        c = census(f'{JWT_A} and again {JWT_A}')
        assert sum(c.values()) == 1, c

    def test_empty_and_none(self):
        assert census(None) == {} and census("") == {}


class TestNonePreserving:
    def test_none_stays_none(self):
        """58 of 216 findings have `impact IS NULL`. Coercing those to "" writes
        empty strings into an export for 27% of findings, and reporting.py's
        `or ""` absorbs it so nothing fails."""
        assert mask(None) is None

    def test_empty_stays_empty(self):
        assert mask("") == ""

    def test_review_wrapper_still_coerces(self):
        from orchestrator.review import redact_secrets
        assert redact_secrets(None) == ""


class TestUrlStaysParseable:
    def test_scheme_host_path_untouched(self):
        from urllib.parse import urlparse
        u = f"http://juice-shop:3000/rest/x?token={JWT_A}&page=1"
        out = mask_url(u)
        p = urlparse(out)
        assert p.scheme == "http" and p.hostname == "juice-shop" and p.port == 3000
        assert p.path == "/rest/x"
        assert JWT_A not in out
        assert "page=1" in out

    def test_url_without_query_is_unchanged(self):
        u = "http://juice-shop:3000/rest/products"
        assert mask_url(u) == u


class TestBenignTextSurvives:
    @pytest.mark.parametrize("text", [
        "http://t/js/app-bundle.js?v=1",                 # -b inside a token
        "nuclei -id CVE-2021-41773",                     # nuclei's -id is a template
        "curl --connect-timeout=10 http://t/",           # -c inside a long flag
        "ffuf -c -w /usr/share/wordlists/common.txt -u http://t/FUZZ",
        "gobuster dir -u http://t -w /w.txt --exclude-length 3748",
        'hydra -l admin -P /w.txt http-post-form '
        '"http://t/l:username=^USER^&password=^PASS^:Invalid credentials"',
    ])
    def test_unchanged(self, text):
        """The hydra case matters: 18 of 540 real `steps.tool_input` rows carry
        `password=^PASS^:Invalid credentials` — a placeholder and a failure
        string. Masking it destroys the only reproduction detail a brute-force
        finding has."""
        assert mask(text) == text

    def test_nikto_scoping_does_not_leak_into_nuclei(self):
        assert mask("nuclei -id dvwa-default-login -u http://t/") == \
            "nuclei -id dvwa-default-login -u http://t/"
        assert mask('nikto -id "admin:hunter2" -h http://t/') != \
            'nikto -id "admin:hunter2" -h http://t/'


class TestTheDownloadableReport:
    """`/report/download` serves data/reports/{sid}.md, which appends the
    complete untruncated command and output of every step straight from memory
    — no SQL filter reaches it. That file is what gets handed to a client.
    """

    @staticmethod
    def _render(tmp_path, steps):
        import asyncio
        import orchestrator.main as M
        M.REPORTS_DIR = tmp_path
        p = asyncio.run(M._save_report_file(
            "s1", "http://juice-shop:3000", "cold", "general", "m", "full",
            len(steps), 0, 10, steps, [], "# Report\n"))
        return Path(p).read_text()

    def test_no_credential_survives_into_the_file(self, tmp_path):
        steps = [{
            "step": 1, "tool": "curl", "phase": "test", "success": True,
            "duration_ms": 10,
            "command": f'curl -H "Authorization: Bearer {JWT_A}" -b "{COOKIE}" http://t/',
            "output": "HTTP/1.1 200 OK\nSet-Cookie: sid=zzz999yyy888",
        }]
        txt = self._render(tmp_path, steps)
        assert JWT_A not in txt
        assert "abc123def456" not in txt
        assert "zzz999yyy888" not in txt
        assert "## Redaction" in txt
        assert "Distinct secrets masked: **3**" in txt

    def test_clean_session_declares_zero_not_absence(self, tmp_path):
        """`applied: yes` with `masked: 0` means the pass ran and found nothing.
        A reader cannot otherwise tell that from a report that never had one."""
        steps = [{"step": 1, "tool": "nmap", "phase": "recon", "success": True,
                  "duration_ms": 10, "command": "nmap -sV juice-shop -p 3000",
                  "output": "3000/tcp open  http"}]
        txt = self._render(tmp_path, steps)
        assert "Applied: **yes**" in txt
        assert "Distinct secrets masked: **0**" in txt


class TestAgainstTheRealCorpus:
    """Every row erlik has actually recorded. Anything masked here must be a
    genuine credential, not an over-firing pattern."""

    @staticmethod
    def _rows():
        db = Path(__file__).resolve().parents[1] / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no recorded corpus")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        out = []
        for tbl, col in (("findings", "evidence"), ("findings", "url"),
                         ("steps", "tool_input")):
            for (v,) in con.execute(
                    f"SELECT {col} FROM {tbl} WHERE {col} IS NOT NULL AND {col} != ''"):
                out.append((f"{tbl}.{col}", v))
        return out

    def test_only_credential_bearing_rows_are_masked(self):
        changed = [(src, v) for src, v in self._rows() if mask(v) != v]
        # Measured: 56 rows, every one carrying either a DVWA default-credential
        # pair or a cookie written by primitives.inject_credentials. Pinned so a
        # broadened pattern that starts eating ordinary evidence fails loudly.
        assert len(changed) == 56, f"{len(changed)} rows masked, expected 56"
        # Justify each masking against the flags primitives.inject_credentials
        # actually writes, rather than a hand-listed set that drifts from them.
        import re as _re
        flag_markers = {_re.split(r"[ =]", tpl)[0]
                        for flags in _AUTH_FLAGS.values() for tpl in flags.values()}
        for src, v in changed:
            justified = (
                any(m in v for m in flag_markers)
                or "password" in v.lower() or "username" in v.lower()
                or "cookie" in v.lower() or "authorization" in v.lower()
            )
            assert justified, f"unexplained masking in {src}: {v[:120]}"

    def test_masking_the_corpus_is_idempotent(self):
        for src, v in self._rows():
            once = mask(v)
            assert mask(once) == once, f"unstable on {src}: {v[:80]}"
