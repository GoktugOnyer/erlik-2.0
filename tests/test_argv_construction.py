"""P0-4: argv transport for single-tool, no-shell commands.

`native_argv` lets a single-program, no-shell command run as a real argv list
(`[docker exec, *argv]`) instead of `bash -c <model-authored-string>`, so shell
metacharacters the model emits are never interpreted. It is OFF by default and a
pure transport swap: every admission guard still runs on the string first, and
the tool receives exactly what bash -c would have passed it.
"""

import pytest

import orchestrator.tool_executor as TE

# curl and sqlmap are enabled but deliberately kept on bash -c (not in ARGV_SAFE).
TOOLS = ["nmap", "whatweb", "wafw00f", "curl", "sqlmap"]


class TestArgvEligible:
    def test_a_clean_single_tool_command_is_eligible(self):
        assert TE._argv_eligible("nmap -sV -p80 127.0.0.1", TOOLS) == \
            ["nmap", "-sV", "-p80", "127.0.0.1"]

    def test_a_quoted_spaced_argument_round_trips(self):
        """The parity case: a quoted argument (as credential injection or a
        spaced value produces) must reconstruct to the exact tokens bash would
        have passed, not be re-split on the inner space."""
        assert TE._argv_eligible('whatweb "http://127.0.0.1/a b"', TOOLS) == \
            ["whatweb", "http://127.0.0.1/a b"]

    @pytest.mark.parametrize("cmd", [
        "nmap 127.0.0.1 | tee out",         # pipe
        "nmap 127.0.0.1; id",               # chain
        "nmap 127.0.0.1 && echo done",      # &&
        "nmap 127.0.0.1 > /tmp/o",          # redirection
        "nmap $(hostname)",                 # command substitution
        "nmap `hostname`",                  # backtick
        "nmap -oN /tmp/o*.txt 127.0.0.1",   # glob
        "nmap -oN ~/out 127.0.0.1",         # tilde
        "nmap 127.0.0.1 -oN {a,b}",         # brace expansion
        "nmap $TARGET",                     # variable
    ])
    def test_a_shell_needing_command_is_ineligible(self, cmd):
        assert TE._argv_eligible(cmd, TOOLS) is None

    def test_a_leading_env_assignment_is_ineligible(self):
        # `NAME=VALUE nmap ...` needs the shell to set the variable.
        assert TE._argv_eligible("TARGET=x nmap -sV 127.0.0.1", TOOLS) is None

    def test_a_sudo_or_timeout_wrapper_is_ineligible(self):
        assert TE._argv_eligible("timeout 60 nmap 127.0.0.1", TOOLS) is None
        assert TE._argv_eligible("sudo nmap 127.0.0.1", TOOLS) is None

    def test_a_tool_not_in_the_registry_stays_on_bash_c(self):
        # curl is enabled but deliberately excluded from ARGV_SAFE.
        assert TE._argv_eligible("curl http://127.0.0.1/", TOOLS) is None

    def test_a_registry_tool_that_is_not_enabled_is_ineligible(self):
        assert TE._argv_eligible("nmap 127.0.0.1", ["curl"]) is None

    def test_unbalanced_quotes_are_ineligible(self):
        assert TE._argv_eligible('nmap "127.0.0.1', TOOLS) is None


class TestSink:
    """`_sync_docker_exec` builds a shell-less argv only when handed one."""

    def _capture(self, monkeypatch):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd

            class R:
                stdout, stderr, returncode = "", "", 0
            return R()

        monkeypatch.setattr(TE.subprocess, "run", fake_run)
        monkeypatch.setattr(TE, "ERLIK_NATIVE", False)
        return seen

    def test_argv_runs_without_a_shell(self, monkeypatch):
        seen = self._capture(monkeypatch)
        TE._sync_docker_exec("nmap -sV 127.0.0.1", 60,
                             argv=["nmap", "-sV", "127.0.0.1"])
        assert seen["cmd"][:3] == [TE.DOCKER_BIN, "exec", TE.CONTAINER_NAME]
        assert seen["cmd"][3:] == ["nmap", "-sV", "127.0.0.1"]
        assert "bash" not in seen["cmd"] and "-c" not in seen["cmd"]

    def test_no_argv_keeps_the_bash_c_path(self, monkeypatch):
        seen = self._capture(monkeypatch)
        TE._sync_docker_exec("nmap -sV 127.0.0.1", 60)
        assert seen["cmd"] == [TE.DOCKER_BIN, "exec", TE.CONTAINER_NAME,
                               "bash", "-c", "nmap -sV 127.0.0.1"]


class TestExecuteToolTransport:
    """The wiring: the transport actually chosen, reported honestly."""

    async def _run(self, monkeypatch, command, native_argv, enabled=("nmap",)):
        seen = {}

        def fake_exec(cmd, timeout, argv=None):
            seen["command"], seen["argv"] = cmd, argv
            return {"output": "ok", "returncode": 0, "error": None}

        monkeypatch.setattr(TE, "_sync_docker_exec", fake_exec)
        monkeypatch.setattr(TE, "ERLIK_NATIVE", True)   # skip the container check
        r = await TE.execute_tool(command, list(enabled),
                                  target_url="http://127.0.0.1",
                                  native_argv=native_argv)
        return r, seen

    async def test_eligible_command_uses_argv_when_on(self, monkeypatch):
        r, seen = await self._run(monkeypatch, "nmap -sV 127.0.0.1", True)
        assert r["executed"] is True
        assert r["transport"] == "argv"
        assert seen["argv"] and seen["argv"][0] == "nmap"

    async def test_off_is_an_exact_no_op(self, monkeypatch):
        r, seen = await self._run(monkeypatch, "nmap -sV 127.0.0.1", False)
        assert r["transport"] == "shell"
        assert seen["argv"] is None

    async def test_ineligible_command_stays_shell_even_when_on(self, monkeypatch):
        # `?` is shell-active, so this falls back to bash -c although the flag is on.
        r, seen = await self._run(monkeypatch, 'whatweb "http://127.0.0.1/?a=1"',
                                  True, enabled=("whatweb",))
        assert r["transport"] == "shell"
        assert seen["argv"] is None


def test_the_agent_loop_passes_the_lever_to_execute_tool():
    """Wiring guard: a run_config key nothing reads is this codebase's signature
    defect (the tunables shipped that way for months). native_argv must reach
    execute_tool, or the lever is inert whatever the dashboard shows."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "orchestrator" / "main.py").read_text()
    assert 'native_argv=runcfg.get("native_argv"' in src

