#!/usr/bin/env python3
"""Run the committed WSTG cases against a REAL application and diff the result
against a committed baseline.

WHY THIS EXISTS. `tests/targets/` proved the cases fire on a planted flaw and
stay silent on a matched control, and every case defect found on 2026-09-05
came from running it. But those targets are mine: I wrote both the flaw and the
case, so a shared misunderstanding of what a real application returns would be
invisible to the whole harness. Juice Shop is not mine and is not synthetic —
it is the application the `juiceshop` profile already aims 10 cases at, and the
one every reported campaign result was produced against.

WHAT IT ASSERTS. Not "these vulnerabilities exist" — that is Juice Shop's
business and it changes between releases. It asserts that **what erlik reports
about a real application does not change without someone saying so**. A case
that silently stops firing looks exactly like a clean target, which is the
defect class this project treats as equal to a crash. So drift fails in BOTH
directions: a finding that disappeared and a finding that appeared are equally
a change nobody declared.

WHAT IT REFUSES TO PRETEND. A case whose tools are not installed is recorded as
`unrunnable` WITH THE MISSING TOOL NAMED, never as a case that found nothing.
On a bare CI runner that is 4 of the 22 planned cases (sqlmap, dalfox, testssl,
wafw00f, whatweb), and folding them into "no findings" would turn a missing
binary into a clean bill of health.

Usage:
    # measure and print, writing nothing
    python scripts/case_baseline.py --base http://127.0.0.1:3000 --profile juiceshop

    # compare against the committed baseline; non-zero exit on any drift
    python scripts/case_baseline.py --base ... --profile juiceshop \\
        --baseline tests/baselines/juiceshop.json

    # record what was measured (review the diff before committing it)
    python scripts/case_baseline.py --base ... --profile juiceshop \\
        --baseline tests/baselines/juiceshop.json --write
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.testcase import find_by_id, load_catalog, run_test_case  # noqa: E402
from orchestrator.testcase.sweep import (PROFILES, catalog_tools,  # noqa: E402
                                         plan_sweep)


def _case_summaries() -> list[dict]:
    """The same shape the API and the planner use.

    Imported from `main` rather than rebuilt here: a second copy of this shape
    is how the planner comes to disagree with the catalogue about what a case
    requires.
    """
    from orchestrator.main import _v2_case_summary
    return [_v2_case_summary(tc) for tc in load_catalog().values()]


def _normalise(result) -> dict:
    """A per-case record that is stable across runs of the same code.

    Deliberately NOT the raw result. Durations, ports, minted collaborator
    names and evidence excerpts all change run to run, and a baseline that
    included them would fail every time while proving nothing. What is kept is
    what an operator would act on: which vulnerability types were reported,
    which steps could not be assessed, and which were refused, denied or
    broken — three different things, kept apart deliberately.
    """
    refused, denied, failed = [], [], []
    for s in result.steps:
        if s.success:
            continue
        e = str(s.error or "")
        # BUCKETED ON THE STRUCTURED FLAGS, not on the wording of the message.
        #
        # This read the error's prefix, knew two of the five that `execute_tool`
        # emits, and filed the rest under "the command did not work". The first
        # CI run against Juice Shop recorded WSTG-CONF-06's `put_probe` as
        # FAILED when safe mode had refused it, and
        # WSTG-AUTHZ-05.redirect_uri_not_validated as FAILED when the agent-lane
        # scope guard had refused it — the second of which was the only visible
        # trace of `payload_hosts` never working end to end.
        #
        # `executed` and `denied` come from the executor itself and are now set
        # on every refusal path, so a guard added later is classified correctly
        # without anyone editing this function. The prefix is consulted only to
        # split scope from authorisation, which is a distinction the flags do
        # not draw, and a refusal with an unrecognised prefix still lands in a
        # refusal bucket rather than being called a breakage.
        if not getattr(s, "executed", True) or getattr(s, "denied", False):
            if e.startswith(("SAFE_MODE:",)):
                denied.append(s.step)       # in scope, not authorised
            else:
                refused.append(s.step)      # a guard would not let it run
        else:
            failed.append(s.step)           # the command itself did not work
    return {
        "findings": sorted({f.vuln_type for f in (result.findings or [])}),
        "not_assessed": sorted({n.step for n in (result.not_assessed or [])}),
        "refused": sorted(set(refused)),
        "denied": sorted(set(denied)),
        "failed_steps": sorted(set(failed)),
    }


def measure(base: str, profile: str, only: set[str] | None = None) -> dict:
    import orchestrator.tool_executor as TE

    plan = plan_sweep(_case_summaries(), base, profile)
    tools = catalog_tools()
    cases, unrunnable = {}, {}

    # NATIVE MODE, set once for this process. The cases shell out to curl, and
    # without it `execute_tool` looks for a Kali container CI does not have and
    # refuses every step -- which reads as "the case found nothing" and would
    # make this entire comparison vacuous. Unlike the pytest harness, nothing
    # else runs in this process, so there is no other test to disturb.
    os.environ["ERLIK_NATIVE"] = "1"
    TE.ERLIK_NATIVE = True

    for entry in plan["runnable"]:
        cid = entry["id"]
        if only and cid not in only:
            continue
        missing = sorted(t for t in tools.get(cid, set()) if not shutil.which(t))
        if missing:
            # NAMED, not folded into "found nothing". A missing binary that
            # reads as a clean result is the exact failure this file exists to
            # catch in the cases themselves.
            unrunnable[cid] = missing
            continue
        started = time.time()
        result = asyncio.run(run_test_case(find_by_id(cid), entry["target"]))
        cases[cid] = _normalise(result)
        print(f"  {cid:<16} {int(time.time() - started):>3}s  "
              f"{len(cases[cid]['findings'])} finding(s) "
              f"{cases[cid]['findings']}", flush=True)

    return {
        "profile": profile,
        "planned": len(plan["runnable"]),
        "skipped": {s["id"]: s.get("reason", "") for s in plan["skipped"]},
        "unrunnable": unrunnable,
        "cases": cases,
    }


def _diff(expected: dict, actual: dict) -> list[str]:
    """Every difference, in both directions.

    A disappeared finding and a new one are both changes nobody declared. The
    first is a case that silently stopped working; the second is either real
    new coverage or a false positive, and neither should land unremarked.
    """
    out = []
    for key in ("skipped", "unrunnable"):
        e, a = expected.get(key) or {}, actual.get(key) or {}
        for cid in sorted(set(e) | set(a)):
            if e.get(cid) != a.get(cid):
                out.append(f"{key}[{cid}]: expected {e.get(cid)!r}, got {a.get(cid)!r}")

    e_cases, a_cases = expected.get("cases") or {}, actual.get("cases") or {}
    for cid in sorted(set(e_cases) | set(a_cases)):
        if cid not in e_cases:
            out.append(f"{cid}: ran, and the baseline does not know about it")
            continue
        if cid not in a_cases:
            out.append(f"{cid}: in the baseline and did not run")
            continue
        for field in ("findings", "not_assessed", "refused", "denied",
                      "failed_steps"):
            e, a = e_cases[cid].get(field) or [], a_cases[cid].get(field) or []
            if e == a:
                continue
            gone, new = sorted(set(e) - set(a)), sorted(set(a) - set(e))
            if gone:
                out.append(f"{cid}.{field}: NO LONGER reported {gone}")
            if new:
                out.append(f"{cid}.{field}: NEWLY reported {new}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1:3000")
    ap.add_argument("--profile", default="", help=f"one of {sorted(PROFILES)}")
    ap.add_argument("--only", default="", help="comma-separated case ids")
    ap.add_argument("--baseline", default="", help="JSON file to compare against")
    ap.add_argument("--write", action="store_true",
                    help="overwrite --baseline with what was measured")
    ap.add_argument("--out", default="",
                    help="always write the measurement here, whatever the "
                         "comparison decides — so a failing run still says "
                         "what it saw rather than only that it disagreed")
    ns = ap.parse_args()

    only = {x.strip() for x in ns.only.split(",") if x.strip()}
    print(f"cases vs {ns.base}  profile={ns.profile or 'none'}\n", flush=True)
    actual = measure(ns.base.rstrip("/"), ns.profile, only or None)

    if ns.out:
        Path(ns.out).parent.mkdir(parents=True, exist_ok=True)
        Path(ns.out).write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")

    print(f"\n{len(actual['cases'])} ran, {len(actual['unrunnable'])} unrunnable "
          f"(missing tools), {len(actual['skipped'])} skipped by the planner")
    for cid, missing in sorted(actual["unrunnable"].items()):
        print(f"  unrunnable {cid}: needs {missing}")

    if not actual["cases"]:
        # A comparison over zero cases agrees with any baseline. CI already
        # makes this check on the pytest suite for the same reason: a green
        # verdict from a path that did nothing is the defect, not the absence
        # of failures.
        print("\nNO CASE RAN. Every one was skipped by the planner or missing "
              "its tools, so this run compared nothing against nothing.")
        return 1

    if not ns.baseline:
        print("\n" + json.dumps(actual, indent=2, sort_keys=True))
        return 0

    path = Path(ns.baseline)
    if ns.write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        print(f"\nwrote {path}")
        return 0

    if not path.exists() or not path.read_text().strip():
        # FAIL rather than silently record. A baseline that writes itself on
        # first sight of a result asserts whatever it happened to see, which is
        # a green check for a comparison that never happened.
        print(f"\nNo baseline at {path}. What was measured:\n")
        print(json.dumps(actual, indent=2, sort_keys=True))
        print("\nReview it, then commit it with --write.")
        return 1

    drift = _diff(json.loads(path.read_text()), actual)
    if drift:
        print(f"\n{len(drift)} change(s) from {path}:")
        for d in drift:
            print(f"  {d}")
        print("\nIf these are intended, re-record with --write and say why in "
              "the commit message.")
        return 1

    print(f"\nno drift from {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
