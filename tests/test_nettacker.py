"""Tests for the Nettacker integration's command construction.

The live scan needs Docker + the kali-tools image, so these cover the pure
argv/launcher logic — scenario selection and the three execution backends
(docker exec default / host-native / custom launcher)."""

import pathlib

import orchestrator.integrations.nettacker as n


def test_argv_default_scenario_uses_recon_profile():
    argv = n._nettacker_argv("http://localhost:3000", "/tmp/o.json")
    assert argv[:2] == ["-i", "localhost"]
    assert "--profile" in argv and argv[argv.index("--profile") + 1] == "scan"
    assert argv[-2:] == ["-o", "/tmp/o.json"]


def test_argv_named_scenario_override():
    argv = n._nettacker_argv("http://localhost:3000", "/tmp/o.json", scenario="tls")
    # tls scenario maps to a stable profile (not the default 'scan')
    prof = argv[argv.index("--profile") + 1]
    assert prof == n.SCENARIOS["tls"]["profile"]


def test_profile_env_wins_over_scenario(monkeypatch):
    monkeypatch.setenv("ERLIK_NETTACKER_PROFILE", "scan,vulns")
    argv = n._nettacker_argv("http://x", "/tmp/o.json", scenario="recon")
    assert argv[argv.index("--profile") + 1] == "scan,vulns"


def test_default_backend_is_docker_exec_reading_stdout(monkeypatch):
    monkeypatch.delenv("ERLIK_NETTACKER_CMD", raising=False)
    monkeypatch.setattr(n, "ERLIK_NATIVE", False)
    monkeypatch.setattr(n, "DOCKER_BIN", "docker")
    cmd, reads_stdout = n._launch_cmd("http://localhost:3000", "/tmp/host.json", None)
    assert reads_stdout is True
    assert cmd[:4] == ["docker", "exec", "kali-tools", "bash"]
    # runs nettacker to a container-side file, then cats it to stdout
    assert cmd[-1].startswith("nettacker ")
    assert cmd[-1].endswith("cat /tmp/erlik_nettacker_scan.json")


def test_custom_launcher_runs_on_host_and_reads_file(monkeypatch):
    monkeypatch.setenv("ERLIK_NETTACKER_CMD", "python3 -m nettacker")
    cmd, reads_stdout = n._launch_cmd("http://x", "/tmp/host.json", None)
    assert reads_stdout is False
    assert cmd[:3] == ["python3", "-m", "nettacker"]
    assert cmd[-2:] == ["-o", "/tmp/host.json"]


def test_native_backend_uses_bare_nettacker(monkeypatch):
    monkeypatch.delenv("ERLIK_NETTACKER_CMD", raising=False)
    monkeypatch.setattr(n, "ERLIK_NATIVE", True)
    cmd, reads_stdout = n._launch_cmd("http://x", "/tmp/host.json", None)
    assert reads_stdout is False
    assert cmd[0] == "nettacker"
    assert cmd[-2:] == ["-o", "/tmp/host.json"]


class TestAnUnrunnableScenarioIsNotOffered:
    """`brute` was selectable in the run-config dropdown and could not work.

    _nettacker_argv emits only -i / --profile / -o; there is no path by which a
    username or password list reaches nettacker. Choosing `brute` therefore
    launched a credential brute-force with nothing to try — against a profile
    whose own description warns it can lock accounts.

    It stays listed and disabled rather than deleted: an operator looking for
    brute-force should learn why it cannot run here, not find it missing.
    """

    def test_brute_is_declared_unavailable(self):
        assert "brute" in n.unavailable_scenarios()

    def test_it_is_still_listed(self):
        """Disabled, not hidden."""
        assert "brute" in n.list_scenarios()

    def test_the_reason_is_the_real_one(self):
        """The claim is that no credential arguments are built. If that ever
        stops being true, this fails and the scenario should be re-enabled."""
        argv = n._nettacker_argv("http://localhost:3000", "/tmp/o.json", scenario="brute")
        assert "--profile" in argv and "brute" in argv
        assert not ({"-u", "-p", "--username", "--password",
                     "--usernames", "--passwords"} & set(argv)), argv

    def test_every_runnable_scenario_really_is_runnable(self):
        """The negative control: nothing else is quietly broken the same way."""
        for name in n.list_scenarios():
            if name in n.unavailable_scenarios():
                continue
            argv = n._nettacker_argv("http://localhost:3000", "/tmp/o.json", scenario=name)
            assert argv[:2] == ["-i", "localhost"], (name, argv)
            assert "-o" in argv, (name, argv)

    def test_the_endpoint_passes_the_reason_through(self):
        from fastapi.testclient import TestClient

        import orchestrator.main as M

        d = TestClient(M.app).get("/api/nettacker-scenarios").json()
        assert "brute" in d["scenarios"], "the name must still be offered"
        assert "brute" in d.get("unavailable", {}), \
            "the UI cannot disable what the endpoint does not flag"

    def test_the_dashboard_disables_flagged_scenarios(self):
        ui = (pathlib.Path(__file__).resolve().parents[1]
              / "dashboard" / "templates" / "index.html").read_text()
        i = ui.index("sData.scenarios")
        blk = ui[i - 400:i + 600]
        assert "sData.unavailable" in blk, "the endpoint's flag is never read"
        assert "o.disabled = true" in blk, "flagged scenarios are still selectable"
