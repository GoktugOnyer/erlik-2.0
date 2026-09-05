"""The real-application baseline, and the reasons it can be worthless.

`scripts/case_baseline.py` runs the committed cases against Juice Shop in CI
and fails when what erlik reports about it changes. That check is only worth
something if the comparison can actually fail, so what is tested here is the
comparison itself — every way a baseline check goes green while proving
nothing:

  * a diff that never reports drift;
  * a diff that reports a disappeared finding but not a new one, or vice versa;
  * a baseline that writes itself on first sight, asserting whatever it
    happened to see;
  * a run where every case was skipped, which agrees with any baseline;
  * a missing tool folded into "this case found nothing";
  * a CI job that stopped invoking the script at all.

The Juice Shop half cannot run here — Docker pulls are blocked by this
environment's egress policy — so the end-to-end measurement happens in CI. The
logic it depends on is exercised here against the local target harness, which
is a real HTTP server the same code path talks to.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

from tests.targets.fixtures import _native_mode, targets, tls_cert  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "case_baseline.py"
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
BASELINE = ROOT / "tests" / "baselines" / "juiceshop.json"


def _module():
    """Import the script by path — it is a CLI, not a package member."""
    spec = importlib.util.spec_from_file_location("case_baseline", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["case_baseline"] = mod
    spec.loader.exec_module(mod)
    return mod


CB = _module()


def _rec(findings=(), not_assessed=(), refused=(), failed=()):
    return {"findings": list(findings), "not_assessed": list(not_assessed),
            "refused": list(refused), "failed_steps": list(failed)}


def _snap(cases, skipped=None, unrunnable=None):
    return {"profile": "juiceshop", "planned": len(cases),
            "skipped": skipped or {}, "unrunnable": unrunnable or {},
            "cases": cases}


class TestTheComparisonCanFail:
    """A baseline check that cannot report drift is a green tick for nothing."""

    def test_identical_snapshots_agree(self):
        """The negative control. Without it every assertion below passes on a
        diff that reports everything as changed."""
        s = _snap({"WSTG-CONF-02": _rec(["Directory Listing"])})
        assert CB._diff(s, s) == []

    def test_a_finding_that_disappeared_is_drift(self):
        """The one that matters most: a case that silently stops firing looks
        exactly like a clean target."""
        before = _snap({"WSTG-CONF-02": _rec(["Directory Listing"])})
        after = _snap({"WSTG-CONF-02": _rec([])})
        d = CB._diff(before, after)
        assert d and "NO LONGER" in d[0], d

    def test_a_finding_that_appeared_is_also_drift(self):
        """New coverage and a new false positive are indistinguishable from
        here, and neither should land unremarked."""
        before = _snap({"WSTG-CONF-02": _rec([])})
        after = _snap({"WSTG-CONF-02": _rec(["Directory Listing"])})
        d = CB._diff(before, after)
        assert d and "NEWLY" in d[0], d

    @pytest.mark.parametrize("field", ["not_assessed", "refused", "failed_steps"])
    def test_every_recorded_field_is_compared(self, field):
        """A field recorded and never diffed is decoration. `refused` in
        particular: a scope guard that started refusing every step would leave
        the findings list empty and look like a clean application."""
        before = _snap({"X": _rec()})
        after = _snap({"X": {**_rec(), field: ["some_step"]}})
        d = CB._diff(before, after)
        assert any(field in x for x in d), (field, d)

    def test_a_case_that_ran_unannounced_is_drift(self):
        d = CB._diff(_snap({}), _snap({"WSTG-CONF-02": _rec()}))
        assert d and "does not know about it" in d[0], d

    def test_a_case_that_stopped_running_is_drift(self):
        d = CB._diff(_snap({"WSTG-CONF-02": _rec()}), _snap({}))
        assert d and "did not run" in d[0], d

    def test_a_tool_that_vanished_is_drift(self):
        """`unrunnable` is where a missing binary is recorded. If it were not
        compared, a runner that lost sqlmap would quietly move a case from
        "ran, found nothing" to "never ran" with no signal at all."""
        d = CB._diff(_snap({}, unrunnable={"WSTG-INPV-05": ["sqlmap"]}),
                     _snap({}, unrunnable={}))
        assert d and "unrunnable[WSTG-INPV-05]" in d[0], d

    def test_a_planner_skip_reason_that_changed_is_drift(self):
        d = CB._diff(_snap({}, skipped={"WSTG-INPV-01": "needs a parameter"}),
                     _snap({}, skipped={"WSTG-INPV-01": "needs a cookie"}))
        assert d and "skipped[WSTG-INPV-01]" in d[0], d


class TestItRefusesToAssertNothing:
    def test_a_missing_baseline_fails_rather_than_writing_itself(self, tmp_path,
                                                                 monkeypatch):
        """A baseline that records itself on first sight asserts whatever it
        happened to see, which is a green check for a comparison that never
        happened."""
        out = tmp_path / "b.json"
        monkeypatch.setattr(CB, "measure",
                            lambda *a, **k: _snap({"X": _rec(["Something"])}))
        monkeypatch.setattr(sys, "argv",
                            ["p", "--base", "http://127.0.0.1:1",
                             "--baseline", str(out)])
        assert CB.main() == 1
        assert not out.exists(), "it wrote the baseline it was meant to check"

    def test_write_records_it_deliberately(self, tmp_path, monkeypatch):
        """The negative control for the above: the recording path must work,
        or the failure is unfixable and someone disables the check."""
        out = tmp_path / "b.json"
        monkeypatch.setattr(CB, "measure",
                            lambda *a, **k: _snap({"X": _rec(["Something"])}))
        monkeypatch.setattr(sys, "argv",
                            ["p", "--base", "http://127.0.0.1:1",
                             "--baseline", str(out), "--write"])
        assert CB.main() == 0
        assert json.loads(out.read_text())["cases"]["X"]["findings"] == ["Something"]

    def test_a_run_where_nothing_ran_fails(self, tmp_path, monkeypatch):
        """A comparison over zero cases agrees with any baseline. CI makes the
        same check on the pytest suite, for the same reason.

        The baseline is WRITTEN FIRST, and that is the whole test. With a
        missing file the run fails on the missing baseline instead, so deleting
        the zero-case guard entirely left this green — it passed for a reason
        that had nothing to do with what it claims to check.
        """
        out = tmp_path / "b.json"
        out.write_text(json.dumps(_snap({})))
        monkeypatch.setattr(CB, "measure", lambda *a, **k: _snap({}))
        monkeypatch.setattr(sys, "argv",
                            ["p", "--base", "http://127.0.0.1:1",
                             "--baseline", str(out)])
        assert CB.main() == 1

    def test_that_baseline_would_otherwise_have_agreed(self, tmp_path,
                                                       monkeypatch):
        """Guards the guard above: the empty snapshot it writes must genuinely
        match, or the failure could be ordinary drift rather than the zero-case
        check firing."""
        assert CB._diff(_snap({}), _snap({})) == []

    def test_drift_fails_and_no_drift_passes(self, tmp_path, monkeypatch):
        out = tmp_path / "b.json"
        out.write_text(json.dumps(_snap({"X": _rec(["A"])})))
        monkeypatch.setattr(sys, "argv",
                            ["p", "--base", "http://127.0.0.1:1",
                             "--baseline", str(out)])
        monkeypatch.setattr(CB, "measure", lambda *a, **k: _snap({"X": _rec(["A"])}))
        assert CB.main() == 0
        monkeypatch.setattr(CB, "measure", lambda *a, **k: _snap({"X": _rec(["B"])}))
        assert CB.main() == 1


class TestTheMeasurementIsHonest:
    # `measure` sets ERLIK_NATIVE for its whole process, which is right for a
    # CLI and wrong inside pytest: native mode removes the container boundary,
    # and test_skills_authoring requires it UNSET. Leaving it set here failed
    # that file while this one passed in isolation — the same cross-test
    # contamination `_native_mode` was extracted to prevent the first time.
    def _measured(self, *a, **kw):
        with _native_mode():
            return CB.measure(*a, **kw)

    def test_a_missing_tool_is_named_not_counted_as_no_findings(self, monkeypatch):
        """The whole point. A case whose binary is absent did not find nothing
        — it did not run, and folding the two together turns a missing package
        into a clean bill of health."""
        monkeypatch.setattr(CB.shutil, "which",
                            lambda t: None if t != "curl" else "/usr/bin/curl")
        got = self._measured("http://127.0.0.1:1", "juiceshop",
                             only={"WSTG-INPV-05"})
        assert got["unrunnable"] == {"WSTG-INPV-05": ["sqlmap"]}, got
        assert "WSTG-INPV-05" not in got["cases"]

    def test_a_case_whose_tools_are_present_is_actually_run(self, targets):
        """Guards the test above: if `measure` marked everything unrunnable the
        assertion there would pass while the script measured nothing at all.

        Run against the local harness rather than Juice Shop — Docker pulls are
        blocked here, so the real application is CI's job.
        """
        got = self._measured(targets["web"], "", only={"WSTG-CONF-02"})
        assert got["unrunnable"] == {}
        assert "WSTG-CONF-02" in got["cases"], got

    def test_running_it_here_does_not_leave_native_mode_on(self, targets):
        """A harness that changes global state for other people's tests is not
        a harness, it is a second bug. This file turned ERLIK_NATIVE on for the
        whole session and broke test_skills_authoring, which requires it unset
        — passing alone and failing in the suite, exactly as before."""
        import os

        import orchestrator.tool_executor as TE
        before = (os.environ.get("ERLIK_NATIVE"), TE.ERLIK_NATIVE)
        self._measured(targets["web"], "", only={"WSTG-CONF-02"})
        assert (os.environ.get("ERLIK_NATIVE"), TE.ERLIK_NATIVE) == before

    def test_a_scope_refusal_is_not_a_step_failure(self):
        """They mean different things to whoever reads the baseline: refused is
        the guard doing its job, failed is the command not working."""
        class _S:
            def __init__(self, step, success, error):
                self.step, self.success, self.error = step, success, error

        class _R:
            steps = [_S("a", False, "scope violation: host 'x' is not allowed"),
                     _S("b", False, "curl: (7) connection refused"),
                     _S("c", True, None)]
            findings = []
            not_assessed = []

        n = CB._normalise(_R())
        assert n["refused"] == ["a"] and n["failed_steps"] == ["b"]


class TestCIActuallyRunsIt:
    """A script nothing invokes is a promise nothing keeps. Six /api/v2/*
    endpoints were once exactly that."""

    JOB = "cases-vs-juiceshop"

    def _job(self):
        d = yaml.safe_load(WORKFLOW.read_text())
        assert self.JOB in d["jobs"], (
            f"the {self.JOB} job is gone; nothing runs the cases against a real "
            f"application any more")
        return d["jobs"][self.JOB]

    def test_the_job_invokes_the_script_with_the_baseline(self):
        runs = " ".join(str(s.get("run", "")) for s in self._job()["steps"])
        assert "scripts/case_baseline.py" in runs
        assert "tests/baselines/juiceshop.json" in runs, (
            "the job runs the script without a baseline, so it measures and "
            "compares against nothing")
        assert "--profile juiceshop" in runs, (
            "without the profile every case is aimed at the base URL, which is "
            "how the SSRF case came to report a finding at a search box")

    def test_the_image_is_pinned(self):
        """On `latest` this job goes red whenever Juice Shop ships a release,
        for reasons that have nothing to do with this repository — and the
        baseline is a statement about one specific build."""
        image = self._job()["services"]["juiceshop"]["image"]
        tag = image.rsplit(":", 1)[-1]
        assert tag not in ("latest", "snapshot", image), f"unpinned image {image!r}"

    def test_it_waits_for_the_application(self):
        """Without the wait the job races startup and records "no findings" for
        a target that was not listening — a clean bill of health from a run
        that never reached anything."""
        runs = " ".join(str(s.get("run", "")) for s in self._job()["steps"])
        assert "127.0.0.1:3000/" in runs and "seq 1" in runs

    def test_the_baseline_matches_the_catalogue_if_it_has_been_recorded(self):
        """Once CI has recorded a baseline, every case in it must still exist.
        A renamed or deleted case would otherwise sit in the file for ever,
        asserted against nothing.

        Skipped while the file is absent: the first CI run is what produces it,
        and failing here would block the run that creates it.
        """
        if not BASELINE.exists():
            pytest.skip("no baseline recorded yet — CI's first run writes it")
        from orchestrator.testcase import load_catalog
        cat = load_catalog()
        recorded = json.loads(BASELINE.read_text())
        unknown = [cid for cid in (list(recorded.get("cases") or {})
                                   + list(recorded.get("unrunnable") or {}))
                   if cid not in cat]
        assert not unknown, f"baseline names cases that no longer exist: {unknown}"
