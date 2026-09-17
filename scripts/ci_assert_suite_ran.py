#!/usr/bin/env python3
"""Assert that a CI run actually exercised the codebase.

A run where everything skipped is green and worthless — the same "confident
output from a path that did nothing" the product itself keeps guarding against.

This used to be an inline heredoc asserting `ran >= 1200`. A bare number goes
stale in one direction only: the suite grew from ~1690 to 2157 and the floor
never moved, so a change that silently skipped 900 tests would have passed. The
floor still exists, because a ratio alone cannot see collection collapsing to ten
tests that all run — but the ratio is what tracks growth, and it needs no
maintenance.

    ci_assert_suite_ran.py junit.xml [--floor N] [--ratio R]
"""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET

# Raise this when the suite grows substantially. Its job is to catch COLLAPSE —
# a collection error that leaves a handful of tests behind — not to track the
# suite's size, which is what --ratio does.
DEFAULT_FLOOR = 2000

# Skips are legitimate here: Docker- and live-service-gated suites skip on a
# runner that has neither. This is the fraction of COLLECTED tests that must
# actually run, and it is what catches a change that silently skips the suite.
#
# Measured on a FRESH CLONE, which is what CI actually checks out: 71 of 3365
# skip on the first run, which is 2.1%. A developer's tree skips 36 (1.1%), and
# calibrating against that figure would have set this threshold too tight.
#
# The 35-test gap is one thing: `data/pentest.db`. `.gitignore` excludes `data/`
# because it holds real client findings, so 33 corpus tests and 2 that inspect
# the live database skip on any checkout that has never been run against
# anything. It is NOT about Docker — the 33 container suites gate on
# ERLIK_DOCKER_TESTS being set, not on the daemon being available, so they skip
# on a developer's machine too and are already inside both figures.
#
# The threshold sits well below even the fresh-clone figure rather than just
# under it: a guard that fires on a healthy run gets removed, and then nothing is
# checked at all.
DEFAULT_RATIO = 0.90


def counts(path: str) -> tuple[int, int, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if not suites:
        raise SystemExit(f"{path}: no <testsuite> element — pytest wrote no results")
    total = sum(int(s.get("tests", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    # A test that errored during collection is not a test that ran.
    errors = sum(int(s.get("errors", 0)) for s in suites)
    return total, skipped, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--floor", type=int, default=DEFAULT_FLOOR)
    parser.add_argument("--ratio", type=float, default=DEFAULT_RATIO)
    args = parser.parse_args()

    total, skipped, errors = counts(args.report)
    ran = total - skipped
    ratio = (ran / total) if total else 0.0
    print(f"{ran} ran, {skipped} skipped, {errors} collection errors, {total} collected "
          f"({ratio:.1%} of collected actually ran)")

    problems = []
    if ran < args.floor:
        problems.append(f"only {ran} tests ran, below the floor of {args.floor} — "
                        f"the suite is not exercising the codebase")
    if total and ratio < args.ratio:
        problems.append(f"only {ratio:.1%} of collected tests ran, below {args.ratio:.0%} — "
                        f"{skipped} skipped, which is more than this suite should need")
    if errors:
        problems.append(f"{errors} collection error(s) — a test that failed to import "
                        f"is not a test that passed")
    for problem in problems:
        print("FAIL:", problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
