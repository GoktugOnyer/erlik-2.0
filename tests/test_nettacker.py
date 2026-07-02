"""Tests for the Nettacker integration's command construction.

The live scan needs Docker + the kali-tools image, so these cover the pure
argv/launcher logic — scenario selection and the three execution backends
(docker exec default / host-native / custom launcher)."""

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
