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
