"""Every assessment left a Docker volume behind, forever.

`erlik-egress:1` inherits `VOLUME /home/mitmproxy/.mitmproxy` from its base image, so every
proxy container creates an anonymous volume — and every sandbox runs a proxy. `Sandbox.close`
removed the container with `docker rm -f`, which leaves that volume in place.

MEASURED on the machine this was found on:

    3443 anonymous volumes    against 12 named ones
    122 created in one day    of assessment runs
    15.4 GB, 84% reclaimable

It is unbounded growth on any long-running installation, and it is INVISIBLE: nothing fails,
no test goes red, docker just gets slower. The gated suite drifted from 8m42s to 13m51s across
this session's runs, which is what sent anybody looking.

Probed per image, because "the containers leak" was a guess until it was not:

    erlik-egress:1            creates 1 anonymous volume, survives `rm -f`, gone with `rm -f -v`
    erlik-integrations:1      creates none
    ghcr.io/zaproxy/zaproxy   creates none

`-v` removes ONLY anonymous volumes. A named volume an operator mounted is untouched, which is
why this is a safe default rather than a destructive one.
"""
import inspect
import os
import re

import pytest


def removal_calls(source):
    """Every `docker rm -f ...` in a source file, as written."""
    return re.findall(r'docker\("rm",\s*"-f"[^)]*\)', source) + \
           re.findall(r'\["docker",\s*"rm",\s*"-f"[^]]*\]', source)


def test_the_sandbox_removes_volumes_with_its_containers():
    """The product path. `close()` is the one that matters — it removes `self.proxy`, the
    container whose image declares the volume."""
    from orchestrator.integrations import runtime

    source = inspect.getsource(runtime)
    calls = removal_calls(source)
    assert calls, "no container removal found; this guard is looking in the wrong place"
    for call in calls:
        assert '"-v"' in call, f"removes a container without its volumes: {call}"


def test_close_is_among_them():
    """Named separately because it is the main leak path, and a guard that passed while
    `close()` alone regressed would be the shape this project keeps removing."""
    from orchestrator.integrations.runtime import Sandbox

    source = inspect.getsource(Sandbox.close)
    assert 'docker("rm", "-f", "-v"' in source, source


@pytest.mark.parametrize("path", [
    "tests/test_integration_docker.py",
    "tests/test_integration_lifecycle.py",
    "tests/test_integration_benchmark.py",
    "tests/test_interactsh_completion.py",
    "tests/test_blind_payloads_engines.py",
])
def test_no_fixture_leaks_either(path):
    """The fixtures spin the same images once per gated run. They leaked at the same rate
    and for the same reason."""
    import pathlib

    source = pathlib.Path(path).read_text()
    for call in removal_calls(source):
        assert '"-v"' in call, f"{path}: {call}"


@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1",
                    reason="set ERLIK_DOCKER_TESTS=1 for the container lab")
@pytest.mark.asyncio
async def test_a_proxy_container_leaves_no_volume_behind():
    """The behavioural half. The assertions above are about what the source says; this is
    about what docker is left holding, which is the thing that actually grew to 3443."""
    from orchestrator.integrations.runtime import IMAGES, docker

    async def volume_count():
        _, out, _ = await docker("volume", "ls", "-q", check=False)
        return len([line for line in out.splitlines() if line.strip()])

    name = "erlik-volume-guard"
    before = await volume_count()
    await docker("run", "-d", "--name", name, "--entrypoint", "sleep",
                 IMAGES["proxy"], "5", check=False)
    running = await volume_count()
    assert running > before, (
        "the proxy image no longer creates an anonymous volume, so this guard is measuring "
        "nothing — check whether the base image changed before deleting it")
    await docker("rm", "-f", "-v", name, check=False)
    assert await volume_count() == before, (
        "the container is gone and its volume is not")
