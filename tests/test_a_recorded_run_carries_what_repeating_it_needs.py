"""What a reader needs to repeat a scan — E-012's reproducibility acceptance.

The acceptance is "a seeded failure reproduces with the same schema digest and seed". The
plan left it open with the measurement to do rather than marked done, because whether
Schemathesis is deterministic under a fixed seed is a property of the TOOL and claiming it
from a recorded number would be the confident-output-from-an-unrun-path defect.

MEASURED against the lab, six runs, and the answer is three facts rather than one:

    --workers 2 (default), seed 1, x4   ordered requests DIFFER run to run
                                        the request SET is identical
                                        the observations are identical
    --workers 1, seed 1, x3             ordered requests identical
    --workers 1, seeds 1 / 987654 / 42  ordered requests IDENTICAL ACROSS SEEDS

The first fact is why `workers` is now a reproduction key: at the default concurrency two
runs with the same schema digest and the same seed record their requests in a different
order, so the recorded set was incomplete for its stated purpose.

THE THIRD FACT IS WHY THIS FILE ASSERTS NO SEED SENSITIVITY. On this fixture the run is
identical across different seeds, so "a seeded failure reproduces with the same seed" is
true and VACUOUS — it reproduces with any seed. A test shaped as "same seed in, same result
out" would pass without the seed doing anything, which is precisely the defect this project
keeps removing. What the seed controls is left UNKNOWN and is recorded as unknown.

A first pass at this measurement did assert seed sensitivity, on two runs that happened to
differ. A third run contradicted it. The ordering was concurrency, not the seed.
"""
import json
import os

import pytest

from orchestrator.integrations.bundle import REPRODUCTION_KEYS

# The container lab, reused rather than re-spun: it builds the same target the rest of the
# docker suite uses. Imported for the fixture, which pytest resolves by name.
from tests.test_integration_docker import lab  # noqa: F401


# ------------------------------------------------- what the record must carry (no docker)


def test_workers_is_a_reproduction_key():
    """The measured gap. Everything else in the set was there; this was not, and a reader
    given the rest cannot repeat the recorded sequence without it."""
    assert "workers" in REPRODUCTION_KEYS
    assert set(REPRODUCTION_KEYS) >= {"schema_sha256", "seed", "workers", "version", "image"}


def test_the_adapter_records_every_reproduction_key_it_owns():
    """Asserted on the call site rather than on a live run: a key in the list that the
    adapter never writes is a bundle field that is always absent, and the bundle would then
    promise a reader something it cannot hand over."""
    import inspect

    from orchestrator.integrations import adapters

    source = inspect.getsource(adapters.SchemathesisAdapter.run)
    for key in ("seed", "workers", "schema_sha256", "version"):
        assert f'"{key}"' in source, f"{key} is a reproduction key the adapter never records"


# --------------------------------------------------------------- what the lab established


pytestmark_docker = pytest.mark.skipif(
    os.environ.get("ERLIK_DOCKER_TESTS") != "1",
    reason="set ERLIK_DOCKER_TESTS=1 for Docker lab tests")


@pytest.mark.docker
@pytestmark_docker
@pytest.mark.asyncio
async def test_a_fixed_seed_reproduces_the_same_requests_and_findings(lab):
    """The half of the acceptance that IS established: at a fixed seed and worker count the
    scan repeats — the same requests and the same observations.

    Compared as a SET, deliberately. At the default --workers 2 the order is concurrency's
    and asserting on it would make this test flaky for a reason that is not a regression;
    the single-worker case below is where order is asserted.
    """
    from orchestrator.integrations.adapters import ADAPTERS, Context
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.runtime import Sandbox

    async def run(seed, workers):
        cfg = AssessmentConfig(
            scope={"allow_hosts": ["target"], "allow_ports": [8080]},
            budget={"stage_seconds": 90, "assessment_seconds": 180,
                    "requests_per_second": 20, "concurrency": workers},
            stages=["schemathesis"], active=True, seed=seed,
            schema_input={"url": "http://target:8080/openapi.json"})
        ctx = Context("test", "schemathesis", "http://target:8080", cfg)
        async with Sandbox(cfg) as sandbox:
            return await ADAPTERS["schemathesis"].run(ctx, sandbox)

    a, b = await run(1, 2), await run(1, 2)
    requests = lambda r: sorted((e.method, e.url) for e in r.endpoints)
    findings = lambda r: sorted(json.dumps(o, sort_keys=True) for o in r.observations)

    assert requests(a), "the scan reached nothing, so repeating it proves nothing"
    assert requests(a) == requests(b)
    assert findings(a) == findings(b)
    assert a.metadata["schema_sha256"] == b.metadata["schema_sha256"]
    assert a.metadata["seed"] == b.metadata["seed"] == 1
    assert a.metadata["workers"] == 2


@pytest.mark.docker
@pytestmark_docker
@pytest.mark.asyncio
async def test_the_recorded_order_is_the_worker_counts_not_the_seeds(lab):
    """The finding that put `workers` in the reproduction keys, asserted directly.

    At one worker the recorded ORDER repeats. The default of two is what makes it vary, so
    the worker count is part of what a reader needs and not a performance detail.
    """
    from orchestrator.integrations.adapters import ADAPTERS, Context
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.runtime import Sandbox

    async def ordered(seed, workers):
        cfg = AssessmentConfig(
            scope={"allow_hosts": ["target"], "allow_ports": [8080]},
            budget={"stage_seconds": 90, "assessment_seconds": 180,
                    "requests_per_second": 20, "concurrency": workers},
            stages=["schemathesis"], active=True, seed=seed,
            schema_input={"url": "http://target:8080/openapi.json"})
        ctx = Context("test", "schemathesis", "http://target:8080", cfg)
        async with Sandbox(cfg) as sandbox:
            r = await ADAPTERS["schemathesis"].run(ctx, sandbox)
        return [(e.method, e.url) for e in r.endpoints], r

    first, r1 = await ordered(1, 1)
    second, _ = await ordered(1, 1)
    assert first and first == second, "single-worker order did not repeat"
    assert r1.metadata["workers"] == 1, "the worker count reaching the record is not the one used"
