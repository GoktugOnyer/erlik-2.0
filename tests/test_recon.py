"""Domain recon: find the attack surface, touch nothing unauthorised.

The dangerous step here is not enumeration. Passive subdomain data comes from
third-party datasets and contacting them harms nobody. The dangerous step is
CONNECTING to what enumeration returned — and passive results routinely include
shared hosting, CDN endpoints, parked names, and hosts belonging to entirely
different companies that happen to share infrastructure.

So the properties under test are:

  A NAME IS NOT PERMISSION. A host that enumeration returned and scope does not
  authorise is written as a pending candidate and NEVER probed.

  A DECLARED RULE IS PERMISSION. If the customer authorised `acme.com` as a
  domain, `vpn.acme.com` is inside what they signed, and probing it needs no
  further approval. That is their decision, not erlik's.

  TOOL OUTPUT IS UNTRUSTED. A hostname from a third-party dataset is rendered
  into a shell command downstream. Anything that is not a plain hostname is
  dropped rather than escaped.
"""

import asyncio
import pathlib

import pytest

from orchestrator import recon as R
from orchestrator import engagement as E


class TestHostnameValidation:
    @pytest.mark.parametrize("h", [
        "acme.com", "vpn.acme.com", "a-b.acme.co.uk", "x1.y2.acme.com",
        "ACME.COM", "acme.com.",
    ])
    def test_real_hostnames_accepted(self, h):
        assert R.valid_hostname(h) is True

    @pytest.mark.parametrize("h", [
        "intranet", "jira", "vpn", "kali-tools", "juice-shop",
    ])
    def test_single_label_internal_names_are_accepted(self, h):
        """A dot is not required. On an internal engagement `intranet` and
        `jira` are ordinary targets, and refusing them would make recon
        unusable exactly where it matters most. What may be CONTACTED is
        decided by scope, not by label count."""
        assert R.valid_hostname(h) is True

    @pytest.mark.parametrize("h", [
        "", "   ", "acme..com", "-acme.com", "acme-.com",
        "acme.com/../etc", "acme.com;id", "acme.com`id`", "acme.com$(id)",
        'acme.com"', "acme com", "acme.com\nevil.com", "*.acme.com",
        "a" * 60 + "." + "b" * 200 + ".com",
    ])
    def test_anything_that_is_not_a_hostname_is_dropped(self, h):
        """Not sanitised — DROPPED. There is no legitimate enumeration result
        that needs a quote in it, and the value reaches a shell downstream."""
        assert R.valid_hostname(h) is False

    def test_the_validator_is_what_gates_shell_use(self):
        """Guard on the guard: if this ever loosened, injection payloads from a
        third-party dataset would reach a command line."""
        import shlex
        bad = "acme.com;curl evil.test"
        assert R.valid_hostname(bad) is False
        assert shlex.quote(bad) != bad, "fixture is not actually dangerous"


class TestToolClassification:
    def test_every_tool_declares_whether_it_touches_the_target(self):
        for name, spec in R.TOOLS.items():
            assert "active" in spec, name
            assert isinstance(spec["active"], bool), name

    def test_passive_and_active_are_split_correctly(self):
        """subfinder queries third parties; httpx opens a connection to the
        customer's host. Gating them the same way would be either uselessly
        strict or dangerously loose."""
        assert R.TOOLS["subfinder"]["active"] is False
        assert R.TOOLS["dnsx"]["active"] is False
        assert R.TOOLS["httpx"]["active"] is True
        assert R.TOOLS["katana"]["active"] is True

    def test_every_tool_declares_whether_recon_invokes_it(self):
        for name, spec in R.TOOLS.items():
            assert "invoked" in spec, name
            assert isinstance(spec["invoked"], bool), name

    def test_invoked_matches_the_tools_recon_actually_runs(self):
        """The flag has to track the code, not the intention.

        The recon panel counts `active and invoked` to tell an operator how
        many tools will touch the customer's hosts. When it counted `active`
        alone it announced two -- httpx and katana -- while katana has no call
        site at all, so the panel promised a crawl that never runs. If someone
        later wires katana up, or drops httpx's call, this fails rather than
        letting the count drift back out of step with the module.
        """
        import re
        src = (pathlib.Path(R.__file__)).read_text()
        called = set(re.findall(r'tool_hint\s*=\s*"([a-z0-9_-]+)"', src))
        assert called, "no execute_tool call sites found -- the parse is wrong"

        declared = {n for n, sp in R.TOOLS.items() if sp["invoked"]}
        assert declared == called, (
            f"TOOLS marks {sorted(declared)} as invoked, but recon.py only calls "
            f"{sorted(called)}"
        )


def _fresh(tmp_path, monkeypatch):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "r.db"))
    return db_mod


class TestNothingUnauthorisedIsProbed:
    def test_out_of_scope_hosts_are_parked_not_probed(self, tmp_path, monkeypatch):
        """THE property. A name enumeration returned is a claim by a third
        party that something exists — not permission to connect to it."""
        db_mod = _fresh(tmp_path, monkeypatch)
        probed: list[list[str]] = []

        async def fake_enum(domain, timeout=180, **kw):
            # a real-looking mix: two under the domain, one that is not
            return ["app.acme.example", "vpn.acme.example"], "2 names"

        async def fake_probe(hosts, timeout=180, **kw):
            probed.append(list(hosts))
            return {h: {"url": f"http://{h}", "status": 200, "tech": []} for h in hosts}

        monkeypatch.setattr(R, "enumerate_passive", fake_enum)
        monkeypatch.setattr(R, "probe_live", fake_probe)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            # Root domain declared, but ONE host explicitly excluded.
            eid = await E.create(db, "Acme", "acme.example")
            await E.add_scope(db, eid, "vpn.acme.example", kind="host", in_scope=False)
            await db.commit()
            rep = await R.run(db, eid)
            await db.close()
            return rep

        rep = asyncio.run(go())
        assert probed == [["app.acme.example"]], (
            f"probed a host scope forbids: {probed}")
        assert rep["authorised"] == ["app.acme.example"]
        assert [p["host"] for p in rep["pending"]] == ["vpn.acme.example"]

    def test_a_declared_domain_authorises_its_subdomains(self, tmp_path, monkeypatch):
        """If the customer signed for acme.com, vpn.acme.com is inside it."""
        db_mod = _fresh(tmp_path, monkeypatch)
        probed: list[list[str]] = []

        async def fake_enum(domain, timeout=180, **kw):
            return ["a.acme.example", "b.acme.example"], "2"

        async def fake_probe(hosts, timeout=180, **kw):
            probed.append(sorted(hosts))
            return {}

        monkeypatch.setattr(R, "enumerate_passive", fake_enum)
        monkeypatch.setattr(R, "probe_live", fake_probe)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.example")
            rep = await R.run(db, eid)
            await db.close()
            return rep

        rep = asyncio.run(go())
        assert probed == [["a.acme.example", "b.acme.example"]]
        assert rep["pending"] == []

    def test_probe_can_be_disabled_entirely(self, tmp_path, monkeypatch):
        """An operator who wants the name list without touching anything."""
        db_mod = _fresh(tmp_path, monkeypatch)
        called = []

        async def fake_enum(domain, timeout=180, **kw):
            return ["a.acme.example"], "1"

        async def fake_probe(hosts, timeout=180, **kw):
            called.append(hosts)
            return {}

        monkeypatch.setattr(R, "enumerate_passive", fake_enum)
        monkeypatch.setattr(R, "probe_live", fake_probe)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.example")
            rep = await R.run(db, eid, probe=False)
            await db.close()
            return rep

        rep = asyncio.run(go())
        assert called == [], "probed despite probe=False"
        assert rep["probed"] == []

    def test_discovered_candidates_do_not_widen_scope(self, tmp_path, monkeypatch):
        """After recon, a pending host must still be refused by the scope
        check. Recon that could authorise its own findings would make the
        approval gate decorative."""
        db_mod = _fresh(tmp_path, monkeypatch)

        async def fake_enum(domain, timeout=180, **kw):
            return ["vpn.other.example"], "1"

        monkeypatch.setattr(R, "enumerate_passive", fake_enum)
        monkeypatch.setattr(R, "probe_live",
                            lambda *a, **k: asyncio.sleep(0, result={}))

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.example")
            # a name outside the declared domain, e.g. from certificate data
            await R.run(db, eid)
            allowed, why = await E.check(db, eid, "http://vpn.other.example")
            await db.close()
            return allowed, why

        allowed, why = asyncio.run(go())
        assert allowed is False
        assert "approved" in why or "no in-scope rule" in why


class TestReportIsHonest:
    def test_an_engagement_with_no_root_domain_says_so(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "")
            rep = await R.run(db, eid)
            await db.close()
            return rep

        assert "no root domain" in asyncio.run(go())["error"]

    def test_a_missing_tool_is_reported_not_silently_empty(self, tmp_path, monkeypatch):
        """An empty result reads as 'the customer has no subdomains', which is
        a very different claim from 'the tool is not installed'."""
        async def no_tool(tool):
            return False

        monkeypatch.setattr(R, "tool_available", no_tool)
        hosts, note = asyncio.run(R.enumerate_passive("acme.example"))
        assert hosts == []
        assert "not installed" in note

    def test_results_outside_the_asked_domain_are_discarded(self, monkeypatch):
        """Passive datasets return artefacts. A name that is not under the
        domain we asked about is not this customer's asset."""
        async def yes(tool):
            return True

        async def fake_exec(cmd, tools, **kw):
            return {"success": True,
                    "output": "app.acme.example\nunrelated.evil.test\nb.acme.example\n"}

        monkeypatch.setattr(R, "tool_available", yes)
        import orchestrator.tool_executor as T
        monkeypatch.setattr(T, "execute_tool", fake_exec)
        hosts, note = asyncio.run(R.enumerate_passive("acme.example"))
        assert hosts == ["app.acme.example", "b.acme.example"]
        assert "discarded" in note


class TestTheOperatorCanSeeWhatWillTouchTheCustomer:
    """`GET /api/engagements/recon/tools` existed with NO caller.

    The handler's own docstring says "an operator authorising a scan should be
    able to see that" — and the DISCOVER SUBDOMAINS button, which CONNECTS to
    the customer's hosts, sat next to nothing that said which tools would run
    or which of them make contact.

    Two different questions are answered, and conflating them is the bug:

      WHICH TOOLS TOUCH THE CUSTOMER — the authorisation question. A passive
      lookup against a third-party dataset and a connection to the client's
      host are not the same act, and only one of them needs permission.

      WHICH ARE MISSING — the "why did this return nothing" question. An absent
      subfinder makes enumeration return an empty list, and an empty list reads
      as "this customer has no subdomains".
    """

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    @classmethod
    def _fn(cls):
        """The body of engLoadReconTools, by brace matching."""
        html = cls._html()
        i = html.index("async function engLoadReconTools")
        depth, start = 0, html.index("{", html.index(")", i))
        for k in range(start, len(html)):
            if html[k] == "{":
                depth += 1
            elif html[k] == "}":
                depth -= 1
                if depth == 0:
                    return html[i:k + 1]
        raise AssertionError("unbalanced braces")

    def test_the_endpoint_reports_both_facts_per_tool(self):
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.main as M
        tools = TestClient(M.app).get("/api/engagements/recon/tools").json()["tools"]
        assert tools, "no tools reported"
        for t in tools:
            assert set(("tool", "active", "installed", "what")) <= set(t), t
        assert any(t["active"] for t in tools), "nothing is marked as contacting the target"
        assert any(not t["active"] for t in tools), "nothing is marked passive"

    def test_the_dashboard_actually_calls_it(self):
        """It had zero callers — the whole defect."""
        html = self._html()
        assert "/api/engagements/recon/tools" in html
        assert "engLoadReconTools" in html
        assert "engLoadReconTools();" in html, "defined but never invoked"

    def test_it_renders_where_the_operator_authorises_contact(self):
        """Next to the buttons, not on some other screen."""
        html = self._html()
        i = html.index('id="eng-recon-tools"')
        j = html.index('onclick="engRecon(true)"')
        assert i < j, "the inventory renders after the button that uses it"
        assert j - i < 2000, "the inventory is not adjacent to the recon buttons"

    def test_active_tools_are_marked_as_contacting_the_target(self):
        block = self._html()
        i = block.index("async function engLoadReconTools")
        body = block[i:i + 2600]
        assert "CONTACTS THE TARGET" in body
        assert "passive" in body

    # These two anchor on the CONDITIONAL, not on the words inside the branch.
    # A first version asserted that "activeMissing" and the warning text merely
    # appeared in the function — and both survive `if (activeMissing.length)`
    # becoming `if (false)`, because the identifier is still declared above and
    # the message still sits in the dead branch. The mutation passed. Same trap
    # as a Dockerfile check satisfied by a comment.
    #
    # This is still source inspection: it proves the branch is reachable, not
    # that it renders correctly. The rendering was verified in a browser
    # against a fabricated degraded toolset.
    def test_a_missing_active_tool_is_called_out(self):
        """Otherwise DISCOVER SUBDOMAINS quietly does less than it says."""
        blk = self._fn()
        assert "if (activeMissing.length) {" in blk, \
            "the warning branch is unreachable"
        assert "will do less than it says" in blk

    def test_a_missing_subfinder_is_called_out_specifically(self):
        """An empty enumeration is not the same claim as "no subdomains"."""
        blk = self._fn()
        assert "if (missing.some(t => t.tool === 'subfinder')) {" in blk, \
            "the subfinder branch is unreachable"
        assert "no subdomains" in blk

    def test_the_two_degraded_branches_are_derived_from_the_data(self):
        """Guard on the guard: both conditions must be computed from the tool
        list, not hardcoded."""
        blk = self._fn()
        assert "const activeMissing = active.filter(t => !t.installed);" in blk
        assert "const missing = tools.filter(t => !t.installed);" in blk

    def test_a_failure_to_read_the_toolset_is_not_silent(self):
        """Rendering nothing would look like "no tools contact the target"."""
        body = self._html()
        i = body.index("async function engLoadReconTools")
        blk = body[i:i + 1400]
        assert "could not read the recon toolset" in blk

    def test_tool_names_are_escaped(self):
        body = self._html()
        i = body.index("async function engLoadReconTools")
        blk = body[i:i + 3000]
        assert "tlEsc(t.tool)" in blk and "tlEsc(t.what)" in blk
