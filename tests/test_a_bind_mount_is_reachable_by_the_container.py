"""A bind mount the container cannot read is a lane that dies before it starts.

Every container the assessment lane runs is `--cap-drop=ALL`, which takes
CAP_DAC_OVERRIDE with it. So root inside those containers does NOT bypass the
permission bits: a 0700 directory or a 0600 file written by the host user is simply
refused. `output` carried the right mode from the start; `policy`, `audit` and
`input` did not, and the whole lane died at startup on a Linux host:

    PermissionError: [Errno 13] Permission denied: '/policy/policy.json'
    RuntimeError: egress proxy did not become ready

IT CANNOT FAIL ON A DEVELOPER MACHINE. Docker Desktop and OrbStack map bind-mount
ownership onto the container user, so the bits never bite on macOS — verified, the
same 0600 file reads fine there. The only place this surfaced was the `docker` CI
job, which runs on pull requests and releases and had never once completed a run
before 2026-09-29. Reproduced instead on a Linux filesystem (a named Docker volume,
chowned to another uid): root with default caps reads the file, root with
--cap-drop=ALL does not.

These tests need no daemon. `_prepare_directories` was extracted from `__aenter__`
for exactly that reason — the alternative is finding out from CI.

Nothing here weakens the host. The privacy boundary is `runtime_root()`, created
0700 and re-chmodded 0700 on every call; these directories live beneath it.
"""
import os
import re
from pathlib import Path

import pytest

from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.runtime import Sandbox


def _sandbox() -> Sandbox:
    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
                              stages=["katana"])
    return Sandbox(config, None)

SOURCE = Path(orchestrator_runtime := __import__(
    "orchestrator.integrations.runtime", fromlist=["x"]).__file__).read_text()

# How each mount is used by the container, which is what decides the mode it needs.
#   "read"  — the container reads files the host wrote
#   "write" — the container creates files of its own
MOUNTS = {
    "policy": "read",
    "input": "read",
    "audit": "write",
    "output": "write",
}


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    box = _sandbox()
    box._prepare_directories()
    return box


def _paths(box) -> dict[str, Path]:
    return {"policy": box.directory / "policy", "audit": box.directory / "audit",
            "input": box.input, "output": box.output}


def test_every_mount_is_traversable_by_another_uid(sandbox):
    """The directory's own mode is all the container ever sees, and without `x` for
    others it cannot reach a single file inside however that file is chmodded."""
    for name, path in _paths(sandbox).items():
        mode = path.stat().st_mode & 0o777
        assert mode & 0o001, (
            f"{name} is {mode:o}; a --cap-drop=ALL container cannot traverse it, so "
            f"every file inside is unreachable regardless of its own mode")


def test_a_mount_the_container_writes_to_is_writable_by_it(sandbox):
    for name, use in MOUNTS.items():
        if use != "write":
            continue
        mode = _paths(sandbox)[name].stat().st_mode & 0o777
        assert mode & 0o002, (
            f"{name} is {mode:o} and the container creates files in it; "
            "a capability-less root cannot")


def test_a_mount_the_container_only_reads_is_not_writable_by_it(sandbox):
    """The other direction, so the fix is not "chmod 777 everything". A read-only
    mount that the world can write to lets anything on the host change what the
    proxy enforces or what an identity claims."""
    for name, use in MOUNTS.items():
        if use != "read":
            continue
        mode = _paths(sandbox)[name].stat().st_mode & 0o777
        assert not mode & 0o002, (
            f"{name} is {mode:o}; the container only reads it, so world-write buys "
            "nothing and lets any local process rewrite the policy the proxy applies")


def test_the_policy_the_proxy_reads_is_readable_by_it(tmp_path, monkeypatch):
    """`policy.json` is written by `private_write`, which is 0600 by design — it is
    the one file here the proxy MUST read, and it was the first thing to fail."""
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    box = _sandbox()
    box._prepare_directories()
    from orchestrator.integrations.security import private_write
    import json
    target = box.directory / "policy" / "policy.json"
    private_write(target, json.dumps(box.policy))
    assert target.stat().st_mode & 0o777 == 0o600, (
        "private_write no longer writes 0600; this test's premise is gone")
    # …which is why __aenter__ chmods it. Asserted against the real source rather
    # than re-run here, because __aenter__ needs a daemon.
    assert re.search(r"policy_file\.chmod\(0o6?44\)", SOURCE), (
        "nothing widens policy.json after private_write, so the proxy cannot read it")


def test_the_mounts_this_file_knows_about_are_all_of_them():
    """Guard on the list. A mount added later with no mode gets no coverage here, and
    the only place that shows up is a CI job that runs on pull requests."""
    # The `-v` is part of the pattern on purpose. Without it this also matched
    # `f"{self.proxy}:/tmp/erlik-ca/..."` — a `docker cp` source path INSIDE the
    # container, which is not a host mount and has no mode to set. The looser
    # version reported it as an uncovered mount on the first run.
    mounted = set(re.findall(r'"-v",\s*f"\{[^}]*\}:/([a-z]+)', SOURCE))
    assert mounted, "no bind mounts found in runtime.py — the scan is broken"
    # A tmpfs is NOT in MOUNTS and should not be: it is created by the kernel, owned
    # by the container, and has no host file to be refused. The worker's `/tmp` is the
    # only one, and it is pinned here so a new tmpfs is looked at rather than assumed
    # harmless — one mounted over `/input` or `/output` would hide the real mount.
    tmpfs = set(re.findall(r'"--tmpfs",\s*"/([a-z]+)', SOURCE))
    assert tmpfs == {"tmp"}, (
        f"runtime.py mounts a tmpfs at {sorted(tmpfs)}. A tmpfs needs no host mode, "
        "but one over a bind-mount path would shadow it — check before adding it here.")
    assert not tmpfs & set(MOUNTS), (
        f"a tmpfs shadows a bind mount: {sorted(tmpfs & set(MOUNTS))}")
    assert mounted == set(MOUNTS), (
        f"runtime.py mounts {sorted(mounted)} and this file covers {sorted(MOUNTS)}. "
        "Add the new one with how the container uses it, and give it a mode in "
        "_prepare_directories.")


def test_the_privacy_boundary_above_them_is_still_private(sandbox):
    """What makes the modes above cost nothing. If this ever stops holding, the
    widening below it becomes real exposure."""
    from orchestrator.integrations.security import runtime_root
    assert runtime_root().stat().st_mode & 0o777 == 0o700, (
        "the runtime root is no longer 0700, so the mount modes above are now the "
        "only thing standing between another local user and client evidence")


def test_it_would_have_caught_the_original(tmp_path, monkeypatch):
    """Guard on the guard: the modes as they were must still be rejected."""
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    box = _sandbox()
    box._prepare_directories()
    for name in ("policy", "audit", "input"):
        _paths(box)[name].chmod(0o700)          # the state that failed on Linux
    failures = [n for n, p in _paths(box).items()
                if not p.stat().st_mode & 0o001]
    assert sorted(failures) == ["audit", "input", "policy"], failures
