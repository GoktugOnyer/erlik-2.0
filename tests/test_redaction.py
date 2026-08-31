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

from orchestrator import redaction as R
from orchestrator.redaction import mask, census, mask_url, PLACEHOLDER_RX
from orchestrator.primitives import _AUTH_FLAGS

from tests import corpus  # noqa: E402

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
        corpus.require("findings")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        out = []
        for tbl, col in (("findings", "evidence"), ("findings", "url"),
                         ("steps", "tool_input")):
            for (v,) in con.execute(
                    f"SELECT {col} FROM {tbl} WHERE {col} IS NOT NULL AND {col} != ''"):
                out.append((f"{tbl}.{col}", v))
        return out

    def test_only_credential_bearing_rows_are_masked(self):
        rows = self._rows()
        changed = [(src, v) for src, v in rows if mask(v) != v]
        # NOT an exact count. This corpus is live and grows with every recorded
        # run, so pinning a number here fails on the next experiment rather than
        # on a real regression — which is exactly what happened.
        #
        # The invariant that matters is the RATE: a pattern broadened enough to
        # start eating ordinary evidence would mask a large fraction, not one
        # more row. Every masked row is separately justified below.
        assert changed, "nothing masked — the control would be vacuous"
        rate = len(changed) / len(rows)
        assert rate < 0.15, f"{rate:.1%} of rows masked ({len(changed)}/{len(rows)})"
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


class TestControlledVocabularyCannotCarryASecret:
    """`vuln_type` sits in _EXPORT_STRUCTURAL, which exempts it from export
    masking on the grounds that it holds a controlled vocabulary.

    That exemption is correct in principle and was false in practice: the value
    is frequently written by a model. Three rows in the recorded corpus have

        vuln_type = 'password="password",username="admin"'

    at severity `critical` — a credential pair in the ONE finding field that is
    deliberately never masked, and which is also broadcast live to the
    dashboard and printed into client reports.

    Two independent guarantees, because the field escapes by three routes:
      * the write path replaces such a label before the INSERT and before the
        WebSocket broadcast (rows recorded from now on are clean); and
      * the export allowlist gains a tripwire, so a row recorded BEFORE the fix
        still cannot leave.
    """

    LEGIT = [
        "SQL Injection", "Cross-Site Scripting (XSS)", "CORS Misconfiguration",
        "Server-Side Request Forgery (SSRF)", "Information Disclosure - Stack Trace",
        "Default Login Credentials", "Broken Authentication", "Arbitrary File Upload",
    ]

    @pytest.mark.parametrize("label", LEGIT)
    def test_real_class_names_pass_through_untouched(self, label):
        """The matcher keys on vuln_type. Mangling legitimate labels would
        silently change every recorded recall number."""
        assert R.safe_label(label) == label

    @pytest.mark.parametrize("bad", [
        'password="password",username="admin"',
        "api_key=sk-live-abc123XYZ456",
        'token="eyJhbGciOiJIUzI1NiJ9"',
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
    ])
    def test_a_label_carrying_a_secret_is_replaced(self, bad):
        out = R.safe_label(bad)
        assert out == R.LABEL_REDACTED
        assert "password" not in out and "sk-live" not in out

    def test_the_replacement_says_why(self):
        """An operator seeing this in a report needs to know the label was
        suppressed, not that the finding is unclassified."""
        assert "secret" in R.LABEL_REDACTED.lower()

    def test_empty_stays_empty(self):
        assert R.safe_label("") == "" and R.safe_label(None) == ""

    def test_the_write_path_applies_it(self):
        """Wiring guard: defining safe_label is not calling it."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert "safe_label" in src
        assert 'f = {**f, "vuln_type": _vt}' in src, (
            "the sanitised label is computed but not substituted before the "
            "INSERT and the broadcast")

    def test_export_tripwire_masks_a_structural_column_holding_a_secret(self):
        """The allowlist is default-ALLOW — the one place in _mask_export_rows
        where a mistake escapes. A row recorded before the write-path fix must
        still not leave."""
        import orchestrator.main as M
        counts: dict = {}
        out = M._mask_export_rows(
            [{"id": 1, "vuln_type": 'password="password",username="admin"',
              "severity": "critical"}], counts)
        assert "password" not in out[0]["vuln_type"]
        assert counts.get("secret"), "the leak was masked but not counted"

    def test_export_tripwire_leaves_ordinary_structural_values_readable(self):
        """Blanket-masking the allowlist would turn every class name into a
        hash and make exports unusable."""
        import orchestrator.main as M
        counts: dict = {}
        out = M._mask_export_rows(
            [{"id": 1, "vuln_type": "SQL Injection", "severity": "high",
              "status": "completed"}], counts)
        assert out[0]["vuln_type"] == "SQL Injection"
        assert out[0]["severity"] == "high"
        assert not counts


class TestTheReportMarkdownItself:
    """The OTHER half of the downloadable file — and the one served by
    `/api/sessions/{id}/report`.

    `TestTheDownloadableReport` above renders with `llm_report="# Report\\n"`, a
    stub. So it only ever exercised the untruncated step log, which was masked,
    and never the hybrid markdown that `_generate_report` builds — which was
    not. That markdown re-reads `steps.tool_input` / `tool_output` from the DB
    and rendered them verbatim into the Command block, the parsed-findings
    block and the raw-output section.

    Measured before the fix: a session's JWT appeared TWICE and its cookie
    THREE times in the file `/report/download` serves, underneath that file's
    own header saying `Applied: **yes**` and `Distinct secrets masked: **3**`.
    The census counted the secrets it masked in the bottom half while the top
    half carried them in clear. A false assurance is worse than none — it is
    the reason someone forwards the file without reading it.
    """

    JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9."
           "QW5vdGhlclNlY3JldFNpZ25hdHVyZVZhbHVlSGVyZQ")
    COOKIE = "PHPSESSID=8f2b91c4de77a05b3e6aa1a9d0"
    CMD = ('curl -s http://juice-shop:3000/rest/admin/all-users '
           '-H "Authorization: Bearer {jwt}" -b "{cookie}"')

    @classmethod
    def _run(cls, tmp_path):
        """The REAL generator, end to end, then the real file writer."""
        import asyncio
        import orchestrator.database as db_mod
        import orchestrator.main as M
        old = db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "r.db"
        M.REPORTS_DIR = tmp_path / "reports"
        cmd = cls.CMD.format(jwt=cls.JWT, cookie=cls.COOKIE)
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await db.execute(
                    "INSERT INTO sessions (id,target_url,system_prompt,status) "
                    "VALUES ('s1','http://juice-shop:3000','p','completed')")
                await db.execute(
                    "INSERT INTO steps (session_id,step_number,phase,tool_called,"
                    "tool_input,tool_output,duration_ms,prompt_sent) "
                    "VALUES ('s1',1,'exploitation','curl',?,?,120,'p')",
                    (cmd, f"HTTP/1.1 200 OK\nSet-Cookie: {cls.COOKIE}\n\n{{}}"))
                await db.execute(
                    "INSERT INTO findings (session_id,vuln_type,severity,url,"
                    "evidence) VALUES ('s1','Broken Access Control','high',"
                    "'http://juice-shop:3000/a','admin route reachable')")
                await db.commit()
                await db.close()

                async def fake_chat(*a, **k):
                    return "stub"
                M.llm_client.chat = fake_chat
                md, _s, _ms = await M._generate_report(
                    "s1", "m", "http://juice-shop:3000", "cold", "general",
                    1, 1, 500)
                steps = [{"step": 1, "tool": "curl", "phase": "exploitation",
                          "success": True, "duration_ms": 120,
                          "command": cmd, "output": f"Set-Cookie: {cls.COOKIE}"}]
                path = await M._save_report_file(
                    "s1", "http://juice-shop:3000", "cold", "general", "m",
                    "full", 1, 1, 500, steps, [], md)
                return md, Path(path).read_text()
            return asyncio.run(go())
        finally:
            db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR = old

    def test_the_served_markdown_carries_no_credential(self, tmp_path):
        """`GET /api/sessions/{id}/report` returns this string."""
        md, _file = self._run(tmp_path)
        assert self.JWT not in md
        assert self.COOKIE not in md
        assert "<jwt:redacted:" in md, "masked, not merely absent"

    def test_the_downloaded_file_carries_no_credential(self, tmp_path):
        """`GET /api/sessions/{id}/report/download` serves this file. It
        embeds the markdown above, so the leak reached it twice over."""
        _md, text = self._run(tmp_path)
        assert text.count(self.JWT) == 0
        assert text.count(self.COOKIE) == 0

    def test_the_redaction_header_is_not_lying(self, tmp_path):
        """The whole point. The file may only DECLARE redaction if the
        declaration holds for the entire file, both halves."""
        _md, text = self._run(tmp_path)
        assert "Applied: **yes**" in text
        assert self.JWT not in text and self.COOKIE not in text

    def test_reproduction_detail_survives_masking(self, tmp_path):
        """NEGATIVE CONTROL, in the other direction: a redactor broad enough to
        eat the request itself would make the report useless for reproducing
        the finding. The URL, the tool and the flags must all still be there."""
        md, _file = self._run(tmp_path)
        assert "curl -s http://juice-shop:3000/rest/admin/all-users" in md
        assert "Authorization: Bearer" in md, "the header NAME is not a secret"
        assert "Broken Access Control" in md
