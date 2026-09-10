"""The two scripts CI depends on to tell the truth about a run.

E-005 asks for CI that covers the Docker suites and produces release evidence;
E-006 asks for a pinned build manifest. Both are only worth having if they fail
when they should, so both are tested rather than trusted.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASSERT_RAN = ROOT / "scripts" / "ci_assert_suite_ran.py"
MANIFEST = ROOT / "scripts" / "release_manifest.py"


def junit(tmp_path, tests, skipped, errors=0):
    path = tmp_path / "junit.xml"
    path.write_text(f'<testsuite tests="{tests}" skipped="{skipped}" errors="{errors}" '
                    f'failures="0" time="1.0"></testsuite>')
    return path


def check(path, *extra):
    return subprocess.run([sys.executable, str(ASSERT_RAN), str(path), *extra],
                          capture_output=True, text=True)


# ------------------------------------------- the guard against a hollow green

def test_a_healthy_run_passes(tmp_path):
    done = check(junit(tmp_path, tests=2192, skipped=35))
    assert done.returncode == 0, done.stderr
    assert "2157 ran" in done.stdout


def test_a_run_where_almost_everything_skipped_fails(tmp_path):
    """The failure this guard exists for: green, complete, and worthless."""
    done = check(junit(tmp_path, tests=2192, skipped=2100))
    assert done.returncode == 1
    assert "below" in done.stderr


def test_a_ratio_guard_catches_mass_skipping_that_a_fixed_floor_would_not(tmp_path):
    """The floor was 1200 while the suite ran ~1690, and never moved as the suite
    grew to 2157 — so a change that silently skipped 900 tests would have passed
    it. A ratio needs no maintenance; that is the half that tracks growth."""
    # The real suite skips 35 of 2192 without Docker, so this is a healthy run.
    done = check(junit(tmp_path, tests=2192, skipped=35), "--floor", "1200")
    assert done.returncode == 0, done.stderr
    # ...and this is not, yet it clears a floor of 1200 comfortably.
    done = check(junit(tmp_path, tests=2192, skipped=900), "--floor", "1200")
    assert done.returncode == 1, "1292 of 2192 passes a floor of 1200 and should not"
    assert "of collected tests ran" in done.stderr


def test_a_collection_collapse_is_caught_by_the_floor_the_ratio_cannot_see(tmp_path):
    """Ten tests collected and all ten running is a perfect ratio."""
    done = check(junit(tmp_path, tests=10, skipped=0))
    assert done.returncode == 1
    assert "floor" in done.stderr


def test_a_collection_error_is_not_a_pass(tmp_path):
    """A test that failed to import is not a test that passed — and the CI
    defect this project just fixed produced exactly that: `asyncio_mode = auto`
    without pytest-asyncio turned every async test into a collection error."""
    done = check(junit(tmp_path, tests=2192, skipped=35, errors=3))
    assert done.returncode == 1
    assert "collection error" in done.stderr


def test_a_report_with_no_testsuite_is_an_error_not_a_pass(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text("<testsuites></testsuites>")
    assert check(path).returncode != 0


# ---------------------------------------------------- the pinned manifest

def test_the_manifest_names_every_image_the_lane_uses(tmp_path):
    from orchestrator.integrations.runtime import IMAGES
    out = tmp_path / "m.json"
    done = subprocess.run([sys.executable, str(MANIFEST), "--out", str(out), "--skip-tools"],
                          capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    manifest = json.loads(out.read_text())
    assert set(manifest["images"]) == set(IMAGES)
    assert manifest["commit"] and manifest["commit"] != "unavailable"


def test_an_absent_image_is_stated_rather_than_omitted(tmp_path, monkeypatch):
    """A manifest that quietly drops an image it could not find would let a
    release claim it was built against something it never had."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_manifest", MANIFEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    absent = module.image("erlik-does-not-exist:0")
    assert absent["present"] is False
    assert absent["reference"] == "erlik-does-not-exist:0"


def test_a_version_banner_is_reduced_to_its_version():
    """katana, nuclei and interactsh-client open with ASCII art and ANSI colour.
    Taking the first non-empty line recorded a row of underscores as a tool
    version, which is worse than recording nothing: it looks like data."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_manifest", MANIFEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    banner = ("\n   __        __\n  / /_____ _/ /____ ____  ___ _\n"
              "\x1b[34m[INF]\x1b[0m Current version: v1.2.2\n")
    assert module._version_line(banner) == "[INF] Current version: v1.2.2"
    assert module._version_line("\n  ____\n  logo only\n") == "unavailable"


def test_stderr_counts_as_output():
    """Three tools print their version to stderr and exit 0. Reading stdout
    alone reported them as unavailable — a manifest asserting a build lacked
    what it in fact had."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_manifest", MANIFEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    said = module._run(sys.executable, "-c",
                       "import sys; sys.stderr.write('v9.9.9\\n')")
    assert said == "v9.9.9"


# --------------------------------------------------------------- gitignore
# E-006: "no unrelated operator files included". The release evidence these
# scripts and the CI jobs write is regenerated every run and must never be
# committed — and the reason is stronger than tidiness. A local
# `pytest -m docker` pointed at a client rather than the lab writes a coverage
# report carrying finding metadata into the checkout root. Untracked but not
# ignored is one `git add -A` away from published.

def _ignored(path):
    done = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT)
    return done.returncode == 0


@pytest.mark.parametrize("artifact", [
    "build-manifest.json",      # scripts/release_manifest.py
    "coverage-report.json",     # ERLIK_COVERAGE_REPORT
    "discovery-comparison.json",  # ERLIK_BENCHMARK_OUTPUT
    "junit.xml",                # the pytest job
    "junit-docker.xml",         # the docker job
    "junit-interactsh.xml",     # the actual-services job
    "junit-defectdojo.xml",
])
def test_generated_release_evidence_is_not_committable(artifact):
    assert _ignored(artifact), (
        f"{artifact} is written by a release job and would be committed; "
        "a run against a client target would publish its findings")


def test_the_recorded_measurement_is_still_tracked():
    """The measurement integration-roadmap.md cites must stay in the repo."""
    recorded = "docs/integration-discovery-comparison.json"
    assert (ROOT / recorded).exists()
    assert not _ignored(recorded)
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", recorded],
                             cwd=ROOT, capture_output=True)
    assert tracked.returncode == 0, "the cited measurement is no longer tracked"


def test_the_release_artifact_patterns_are_anchored_to_the_repo_root():
    """The anchoring claim, tested rather than asserted.

    The first version of this checked only that the ROOT artifacts are ignored,
    which passes identically with or without the leading slashes — so it could
    not catch the rationale beside it being wrong. (It was: the comment claimed
    an unanchored pattern would swallow
    docs/integration-discovery-comparison.json. It would not — gitignore matches
    whole path components, not substrings, and that basename never matched.)

    What anchoring actually buys is this: a same-named file in a subdirectory is
    a different file and must not be silently ignored.
    """
    for name in ("build-manifest.json", "coverage-report.json",
                 "discovery-comparison.json", "junit.xml"):
        assert _ignored(name), f"{name} at the root should be ignored"
        nested = f"docs/{name}"
        assert not _ignored(nested), (
            f"{nested} is ignored — the pattern for {name} lost its leading "
            "slash, so it now hides same-named files anywhere in the tree")


# -------------------------------------------------------------- README figures
# The README quotes a fresh-clone suite figure and then breaks it down by
# reason. Twice now that text has been wrong: once because the total went stale
# (1674 against a suite of 2134), and once because I wrote a breakdown summing
# to 44 under a total of 68 — I had counted distinct skip LOCATIONS instead of
# summing the `SKIPPED [n]` counts pytest prints.
#
# This does not re-run the suite to check the total; that would be circular and
# slow. It checks the claim is internally consistent, which is the half a reader
# can't verify at a glance and the half that was actually wrong.

def _readme():
    return (ROOT / "README.md").read_text()


def test_the_readme_skip_breakdown_sums_to_the_total_it_claims():
    import re
    text = _readme()
    total = re.search(r"\*\*(\d+) passed, (\d+) skipped\*\* on its first run", text)
    assert total, "the README no longer states a fresh-clone figure in the expected form"
    claimed = int(total.group(2))
    rows = re.findall(r"^\| (\d+) \| (?!Reason)(.+?) \|$", text, re.M)
    assert rows, "the skip breakdown table is gone or reshaped"
    counted = sum(int(n) for n, _ in rows)
    assert counted == claimed, (
        f"the README breaks {claimed} skips down into rows summing to {counted}; "
        "pytest prints `SKIPPED [n]` per location, so the n must be summed")


def test_the_readme_lane_count_matches_the_parser():
    """The one number in the README that a catalogue change silently invalidates.

    `9 of the 29` survived the catalogue growing to 32 and the lane to 12,
    because nothing asked. This asks.
    """
    import re
    from orchestrator.integrations.inventory import executable_test_cases
    from orchestrator.testcase.loader import load_catalog

    stated = re.search(r"runs \*\*(\d+) of the (\d+)\*\* catalogue cases", _readme())
    assert stated, "the README no longer states the lane coverage in the expected form"
    runnable, total = int(stated.group(1)), int(stated.group(2))
    assert runnable == len(executable_test_cases()), (
        f"README says {runnable} runnable; the parser answers "
        f"{len(executable_test_cases())}")
    assert total == len(load_catalog()), (
        f"README says {total} catalogue cases; the catalogue holds "
        f"{len(load_catalog())}")


def test_every_lane_yes_in_the_readme_table_is_one_the_parser_agrees_with():
    """A wrong `yes` tells an operator a case runs when it does not."""
    import re
    from orchestrator.integrations.inventory import executable_test_cases, COLLECTOR_CASES

    runnable, collector = set(executable_test_cases()), set(COLLECTOR_CASES)
    rows = re.findall(r"^\| (WSTG-[A-Z0-9.b-]+) \| .+? \| (yes|—|via collector) \|$",
                      _readme(), re.M)
    assert len(rows) >= 30, f"only parsed {len(rows)} catalogue rows from the README"
    for case_id, mark in rows:
        if mark == "yes":
            assert case_id in runnable, f"{case_id} is marked runnable and is not"
        elif mark == "via collector":
            assert case_id in collector, f"{case_id} is marked collector-run and is not"
        else:
            assert case_id not in runnable, f"{case_id} runs, but the table says it does not"


def test_the_readme_parameter_dependency_count_is_current():
    """`WSTG-CLNT-04, WSTG-INPV-11.2 and WSTG-INPV-18` was true when written.

    Then the three WSTG-INPV-05.x injection cases arrived and nothing revisited
    the sentence, so a claim about 3 cases silently came to describe 6 — the
    same way `9 of the 29` outlived a catalogue that had grown to 32.
    """
    import re
    from orchestrator.integrations.inventory import executable_test_cases
    from orchestrator.testcase.loader import load_catalog

    catalogue = load_catalog()
    actual = {c for c in executable_test_cases()
              if any("{{parameter}}" in step.command for step in catalogue[c].steps)}
    stated = re.search(r"(\d+) of the (\d+) interpolate `\{\{parameter\}\}`", _readme())
    assert stated, "the README no longer states the parameter dependency in the expected form"
    assert int(stated.group(1)) == len(actual), (
        f"README says {stated.group(1)} cases interpolate the parameter; "
        f"{len(actual)} do: {sorted(actual)}")
    assert int(stated.group(2)) == len(executable_test_cases())


# ------------------------------------------------- the documented DefectDojo table
# docs/integrations.md now carries a table of accepted and refused export bodies,
# QUOTING the validator's error text. An operator reads that table to work out why
# their first import was refused, so the quotes have to stay true to the code.

DOJO_TABLE = [
    (dict(action="import", engagement_id=7, test_title="Erlik assessment"), None),
    (dict(engagement_id=7, test_title="Erlik assessment"),
     "reimport requires an existing test_id, without engagement_id or test_title"),
    (dict(action="import", engagement_id=7, test_title="Erlik assessment", test_id=42),
     "initial import requires an existing engagement_id and test_title, without test_id"),
    (dict(action="reimport", test_id=42), None),
    (dict(action="reimport", test_id=42, engagement_id=7),
     "reimport requires an existing test_id, without engagement_id or test_title"),
]


@pytest.mark.parametrize("body,expected", DOJO_TABLE)
def test_the_documented_export_table_matches_the_validator(body, expected):
    from orchestrator.integrations.defectdojo import ExportConfig
    kwargs = dict(server="https://dojo.lab.internal", secret_id="handle", **body)
    if expected is None:
        ExportConfig(**kwargs)       # documented as accepted; must not raise
        return
    with pytest.raises(Exception) as exc:
        ExportConfig(**kwargs)
    assert expected in str(exc.value), (
        f"docs/integrations.md quotes {expected!r}; the validator now says "
        f"{str(exc.value)!r}")


@pytest.mark.parametrize("expected", sorted({m for _, m in DOJO_TABLE if m}))
def test_every_error_the_docs_quote_appears_in_the_docs(expected):
    """Catches the table being edited to say something the validator never says."""
    assert expected in (ROOT / "docs" / "integrations.md").read_text()


@pytest.mark.parametrize("server,ok", [
    ("https://dojo.lab.internal", True),
    ("https://dojo.lab.internal:443", True),     # documented as normalised away
    ("http://dojo.lab.internal", False),         # documented as refused
    ("https://dojo.lab.internal/dojo", False),
    ("https://u:p@dojo.lab.internal", False),
    ("https://dojo.lab.internal?x=1", False),
])
def test_the_documented_server_origin_rule(server, ok):
    from orchestrator.integrations.defectdojo import ExportConfig
    make = lambda: ExportConfig(server=server, secret_id="h", action="reimport", test_id=42)
    if not ok:
        with pytest.raises(Exception):
            make()
        return
    cfg = make()
    assert cfg.server == "https://dojo.lab.internal", (
        "the docs say `:443` is accepted and normalised away; got " + cfg.server)


def test_the_readme_fresh_clone_total_matches_what_the_suite_collects():
    """The guard that would have caught this drifting, twice, in one sitting.

    The README's fresh-clone figure cannot be re-derived here — it needs an
    actual clone with no `data/pentest.db`. But `passed + skipped` must equal the
    number of tests the suite COLLECTS, and that is checkable. Both times the
    figure went stale it was because tests were added after it was measured, and
    both times this assertion would have failed on the same commit.
    """
    import re
    stated = re.search(r"\*\*(\d+) passed, (\d+) skipped\*\* on its first run", _readme())
    assert stated, "the README no longer states a fresh-clone figure in the expected form"
    claimed_total = int(stated.group(1)) + int(stated.group(2))

    done = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q",
                           "-p", "no:cacheprovider", "tests/"],
                          cwd=ROOT, capture_output=True, text=True)
    collected = re.search(r"(\d+) tests collected", done.stdout)
    assert collected, f"could not read the collected count from:\n{done.stdout[-800:]}"
    assert claimed_total == int(collected.group(1)), (
        f"README claims {stated.group(1)} passed + {stated.group(2)} skipped = "
        f"{claimed_total}, but the suite collects {collected.group(1)}. Re-measure "
        f"from a fresh clone: tests were added or removed since that figure was taken.")
