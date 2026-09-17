"""Where a tool may write on the ORCHESTRATOR — the complement of the read-side floor.

Increment 43 closed the read side: `curl -d @/etc/passwd https://target/` took a file off this
machine and posted it. A command can also put bytes here — `curl -o ~/.ssh/authorized_keys`,
`nmap -oN /etc/cron.d/x`, `... > ~/.erlik/secrets/a.json`. The host running erlik holds the
secret store, other engagements' evidence and the operator's own files.

NOT A SAFE-MODE RULE, and that is the load-bearing decision. Safe mode answers "does this
engagement authorise destructive testing OF THE TARGET", and `ERLIK_SAFE_MODE=0` says yes.
That is a different authorisation from "erlik may write anywhere on the operator's disk", and
collapsing them would mean an authorised destructive engagement silently unlocked the
filesystem. This floor holds either way, which is asserted below.

THE ROOTS COME FROM WHAT REAL RUNS DO, not from taste. Measured over the 1630 recorded
commands in the corpus: 14 (0.9%) write anything, and every target is either under /tmp or a
bare relative name landing in the working directory. Nothing writes to an absolute path
outside /tmp.

The rule was wrong THREE times before it was right, and each corpus caught a different one.
A case-insensitive flag match ate every `-d` (curl's data) as `-D` (its dump-header) and
called 17.9% of commands writers. `-w` was included as "write-out" when it is a WORDLIST for
ffuf, gobuster and hydra and a stdout FORMAT STRING for curl. And `-o /dev/null` -- the
standard way to discard a body while keeping headers, used by five steps of the shipped
WSTG-CLNT-04 -- was refused until the CATALOGUE sweep found it. The recorded corpus covers
the agent lane and the catalogue covers the deterministic one; both are tests below.
"""
import os
import pathlib
import sqlite3

import pytest

from tests import corpus

from orchestrator.tool_executor import (
    write_confinement_violation, write_roots, write_targets)


# ---------------------------------------------------------------- what it refuses


@pytest.mark.parametrize("command,why", [
    pytest.param("curl -o /root/.ssh/authorized_keys http://t/k",
                 "the operator's own account", id="-o into a home directory"),
    pytest.param("nmap -oN /etc/cron.d/erlik target",
                 "a scheduled-task directory", id="-oN into /etc"),
    pytest.param("curl http://t/x > /usr/local/bin/erlik",
                 "a binary on PATH", id="redirect over a binary"),
    pytest.param("curl http://t/x | tee /etc/hosts",
                 "tee is a write like any other", id="tee into /etc"),
    pytest.param("curl -D /var/log/erlik.headers http://t/x",
                 "-D is curl's dump-header and names a file", id="-D outside the roots"),
])
def test_a_write_outside_the_roots_is_refused(command, why):
    reason = write_confinement_violation(command)
    assert reason, why
    assert "outside the directories erlik may write to" in reason
    assert "ERLIK_WRITE_ROOTS" in reason, "the operator is not told what to change"


def test_a_relative_path_cannot_climb_out_of_the_working_directory(monkeypatch, tmp_path):
    """`-oN nmap_results.txt` is how every recorded run writes. The same shape pointed
    somewhere else is not, and resolving before comparing is what separates them.

    The escape is CONSTRUCTED from the roots rather than written as a fixed `../../..`. A
    literal one is environment-dependent: measured in a fresh clone whose working directory
    sits under /tmp, climbing four levels lands back INSIDE an allowed root, and the test
    failed while the rule was behaving correctly.
    """
    working = tmp_path / "engagement" / "run"
    working.mkdir(parents=True)
    monkeypatch.chdir(working)
    monkeypatch.setenv("ERLIK_WRITE_ROOTS", str(working))
    assert not write_confinement_violation("nmap -oN nmap_results.txt target")

    # Anchored at the FILESYSTEM root, not at tmp_path's parent. On this machine pytest's
    # tmp_path lives under /private/var, but on Linux it lives under /tmp -- which is itself
    # an allowed root, so climbing out of tmp_path would land somewhere writing IS permitted
    # and the test would fail there while the rule behaved correctly. Nothing is under "/"
    # alone, so this target is outside every root on either platform.
    escape = os.path.relpath("/erlik-write-confinement-probe", working)
    assert escape.startswith(".."), escape
    assert write_confinement_violation(f"curl http://t/x > {escape}"), (
        f"{escape!r} resolves outside {working} and was allowed")


def test_the_target_may_not_choose_the_filename():
    """`curl -O` names the file from the REMOTE url's last segment, so a target could drop
    something over `nmap_results.txt` in the working directory. No recorded command uses it,
    so refusing costs nothing measurable."""
    reason = write_confinement_violation("curl -O http://t/nmap_results.txt")
    assert reason and "TARGET choose the filename" in reason


# ------------------------------------------------------------------ what it allows


@pytest.mark.parametrize("command", [
    pytest.param("nmap -sV -p 3000 juice-shop --open -oN nmap_results.txt",
                 id="nmap into the working directory"),
    pytest.param("ffuf -u http://t/FUZZ -w /usr/share/dirb/wordlists/common.txt "
                 "-o /tmp/ffuf_results.json", id="ffuf into /tmp"),
    pytest.param("hashcat -m 1600 -a 0 -o output.txt /usr/share/wordlists/rockyou.txt",
                 id="hashcat into the working directory"),
    pytest.param('echo \'{"email":"a@b.c"}\' > /tmp/login.json && curl -d @/tmp/login.json '
                 'http://t/login', id="the agent's login idiom"),
])
def test_the_shapes_real_runs_use_are_allowed(command):
    assert not write_confinement_violation(command)


@pytest.mark.parametrize("command", [
    pytest.param('curl -d "<script>alert(1)</script>" http://t/x',
                 id="an XSS payload is not a redirect"),
    pytest.param("jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt",
                 id="a placeholder is the other bracket"),
    pytest.param("ffuf -u http://t/FUZZ -w /usr/share/wordlists/common.txt",
                 id="-w is a wordlist, not write-out"),
    pytest.param('curl -w "%{http_code}" http://t/x',
                 id="curl's -w is a stdout format string"),
    pytest.param("arjun -u http://t/rest/search -t 5 -d 1",
                 id="-d is data, and -D is the one that names a file"),
])
def test_the_false_positives_the_corpus_found_stay_allowed(command):
    """Each of these was refused by a version of this rule before the corpus rejected it."""
    assert not write_confinement_violation(command), write_targets(command)


# ------------------------------------------ it is not gated on the target authorisation


def test_authorising_destructive_testing_does_not_unlock_the_filesystem(monkeypatch):
    """The decision this file exists to make. `ERLIK_SAFE_MODE=0` authorises acting on the
    TARGET; it is not consent to write to the operator's disk, and a floor that read it as
    consent would hand an authorised engagement the machine."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    assert write_confinement_violation("curl -o /root/.ssh/authorized_keys http://t/k")


def test_the_roots_are_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("ERLIK_WRITE_ROOTS", str(tmp_path))
    assert not write_confinement_violation(f"curl -o {tmp_path}/out.json http://t/x")
    assert str(tmp_path.resolve()) in write_roots()


def test_the_data_directory_is_a_root(monkeypatch, tmp_path):
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    (tmp_path / "runtime").mkdir()
    assert not write_confinement_violation(
        f"curl -o {tmp_path / 'runtime' / 'x.json'} http://t/x")


# --------------------------------------------------- it reaches every execution path


async def test_the_runner_refuses_before_the_request_is_made():
    """A caller that brought its own executor reaches neither gate inside `execute_tool` —
    the defect E-033 recorded about the mutation refusal, and the reason this sits on the
    runner's floor too."""
    from orchestrator.testcase.runner import run_test_case
    from orchestrator.testcase.schema import TestCase as Case, TestStep as Step

    sent = []

    async def recorder(cmd, *a, **kw):
        sent.append(cmd)
        return {"success": True, "output": "", "duration_ms": 1, "error": None}

    case = Case(id="T", name="t", category="config", severity="low", steps=[Step(
        name="s", tool="curl", command="curl -o /root/.ssh/authorized_keys http://app.test/k")])
    result = await run_test_case(
        case, {"url": "http://app.test/x",
               "scope": {"allow_hosts": ["app.test"], "allow_ports": [80]}},
        executor=recorder, allow_llm=False)
    assert sent == [], f"the write was attempted: {sent}"
    assert result.steps[0].skipped is True
    assert result.steps[0].error.startswith("WRITE_CONFINEMENT: ")


def test_execute_tool_applies_it_too():
    """The other path. Asserted on the call site rather than the function, because a guard
    nothing calls is the shape this project keeps removing — and increment 42's ablation
    found exactly that gap in the free-space preflight."""
    import inspect

    from orchestrator import tool_executor

    assert "write_confinement_violation(sanitized)" in inspect.getsource(
        tool_executor.execute_tool)


# ----------------------------------------------------- and the corpus is the evidence


def test_the_recorded_corpus_still_passes_this_rule():
    """The roots are derived from what real runs do. If a future edit broadens the rule, the
    corpus is what says so — it caught two of the three wrong versions already."""
    db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
    if not db.exists():
        pytest.skip("no recorded corpus")
    # The same gate the sibling corpus test uses. A store that exists but holds no steps is
    # "not present" for this purpose, and asserting non-emptiness instead made the test fail
    # in a fresh clone rather than skip there.
    corpus.require("steps")
    rows = [r[0] for r in sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
        "SELECT tool_input FROM steps WHERE tool_input IS NOT NULL AND tool_input != ''")]
    writers = [c for c in rows if write_targets(c)]
    rate = len(writers) / len(rows)
    assert rate < 0.05, (
        f"{rate:.1%} of recorded commands are read as writers ({len(writers)}/{len(rows)}); a "
        f"broadened extractor is refusing ordinary traffic")
    # Every recorded write goes to /tmp or the working directory, so none is refused.
    refused = [c for c in writers if write_confinement_violation(c)]
    assert refused == [], [c[:80] for c in refused]


def test_no_shipped_catalogue_step_is_refused():
    """The catalogue is the other corpus, and the first version of this rule missed it.

    `-o /dev/null` is the standard way to discard a response body while keeping the headers,
    and five steps of `WSTG-CLNT-04` use exactly that. The recorded command corpus covers the
    agent lane; this covers the deterministic one, and between them a broadened rule has
    nowhere to hide.
    """
    import yaml

    catalogue = pathlib.Path(__file__).resolve().parents[1] / "tests_catalog"
    refused, steps = [], 0
    for path in sorted(catalogue.rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        for step in (document or {}).get("steps") or []:
            command = step.get("command") or ""
            if not command:
                continue
            steps += 1
            if write_confinement_violation(command):
                refused.append(f"{path.name}:{step.get('name')}")
    assert steps > 50, f"only {steps} catalogue steps found; this test stopped looking"
    assert refused == [], refused


@pytest.mark.parametrize("device", ["/dev/null", "/dev/stdout", "/dev/stderr"])
def test_a_write_that_goes_nowhere_is_allowed(device):
    assert not write_confinement_violation(f"curl -s -D - -o {device} http://t/x")


def test_the_null_allowance_is_a_named_list_not_the_whole_of_dev():
    """`/dev/sda` is also under `/dev/`."""
    from orchestrator.tool_executor import NULL_DEVICES

    assert "/dev/sda" not in NULL_DEVICES
    assert write_confinement_violation("curl -o /dev/sda http://t/x")
