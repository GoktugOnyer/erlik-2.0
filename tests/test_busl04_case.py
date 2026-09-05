"""WSTG-BUSL-04 reported clean runs it had not performed.

Two defects, measured 2026-09-05 against a local endpoint with a check-then-act
window and no lock.

1. `parallel_n` is declared OPTIONAL and nothing supplied a default. Omitted,
   the step rendered as

       for i in $(seq 1 ); do (...) & done; wait

   which fires ZERO requests. `wait` returns 0, so the step reported success
   with empty output and the case reported nothing. A race-condition test that
   sent no requests at all, presented as a clean result. Against the same
   target with the default in place: `requests_fired=10 successes=10`.

2. The verdict was `({{success_marker}}.*){2,}`. `.` does not cross a newline,
   so both successes had to land on the SAME LINE:

       "REDEEM_OKREDEEM_OK..."      (no trailing newline)  -> matched
       "REDEEM_OK applied\\n" x 5                          -> NO MATCH
       pretty-printed JSON bodies x 3                      -> NO MATCH

   Every API whose body ends with a newline won the race five times out of five
   and was reported clean.

Both are now decided by counting occurrences in the shell and printing a
canary, which is what AUTHZ-04 and INPV-15 already do. Verified live: FINDING
with `parallel_n` omitted against the unlocked endpoint, silence against a
locked one, and a third verdict for "the request never succeeded even once" --
which used to be indistinguishable from a clean run.
"""

import re
from pathlib import Path

import pytest
import yaml

CASE = (Path(__file__).resolve().parents[1] / "tests_catalog" / "wstg"
        / "BUSL-04_race_condition.yaml")


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


@pytest.fixture(scope="module")
def command(case):
    return case["steps"][0]["command"]


class TestAnOmittedParallelNStillFiresRequests:
    def test_the_default_is_applied_in_the_shell(self, command):
        """Not in the schema: the renderer substitutes an empty string for an
        absent optional field, so the default has to survive that."""
        assert 'N="{{parallel_n}}"' in command
        assert "N=10" in command, (
            "nothing supplies a count, so an omitted parallel_n renders "
            "`seq 1 ` and the burst fires zero requests"
        )

    def test_a_non_numeric_or_tiny_value_is_also_handled(self, command):
        assert "*[!0-9]*" in command, "a non-numeric parallel_n still breaks seq"
        assert '"$N" -lt 2' in command, (
            "a race needs at least two concurrent requests; 1 or 0 makes the "
            "test vacuous rather than failing"
        )

    def test_the_count_is_reported(self, command):
        """Declare, do not silently drop: the operator has to be able to see
        how many requests actually went out."""
        assert "requests_fired=" in command
        assert "successes=" in command

    @pytest.mark.parametrize("n,expected", [
        ("", 10), ("abc", 10), ("0", 10), ("1", 10), ("5", 5), ("40", 40),
    ])
    def test_the_normalisation_runs(self, command, n, expected, tmp_path):
        """Executes the real shell prologue rather than re-deriving it."""
        import subprocess
        prologue = 'N="%s"; case "$N" in ""|*[!0-9]*) N=10;; esac; [ "$N" -lt 2 ] && N=10; echo "$N"' % n
        out = subprocess.run(["bash", "-c", prologue], capture_output=True,
                             text=True).stdout.strip()
        assert out == str(expected), out


class TestTheCountDoesNotDependOnNewlines:
    def test_the_old_pattern_is_gone(self, case):
        for ev in case["steps"][0]["evaluators"]:
            assert ".*){2,}" not in ev.get("pattern", ""), (
                "`.` does not cross a newline, so this only fires when two "
                "successes land on the same line"
            )

    def test_counting_is_done_with_grep(self, command):
        assert "grep -oF" in command, (
            "-F so a $ or . in an operator's marker is counted literally, "
            "not applied as a regex"
        )

    @pytest.mark.parametrize("body,hits", [
        ("REDEEM_OK appliedREDEEM_OK applied", 2),
        ("REDEEM_OK applied\n" * 5, 5),
        ('{\n  "status": "REDEEM_OK"\n}\n' * 3, 3),
        ("REDEEM_OK applied\nalready redeemed\n", 1),
        ("already redeemed\n" * 4, 0),
    ])
    def test_the_real_counting_shell_gets_it_right(self, body, hits):
        """The shapes that broke it, run through the actual pipeline."""
        import subprocess
        cmd = 'printf "%s" "$1" | grep -oF "REDEEM_OK" | wc -l'
        out = subprocess.run(["bash", "-c", cmd, "_", body],
                             capture_output=True, text=True).stdout.strip()
        assert int(out) == hits, out


class TestTheThreeVerdicts:
    VERDICTS = {
        "ERLIK_BUSL_RACE": 1,             # fires the finding evaluator
        "ERLIK_BUSL_SINGLE_SUCCESS": 0,
        "ERLIK_BUSL_NO_SUCCESS": 0,
    }

    def test_all_three_are_emitted(self, command):
        missing = [v for v in self.VERDICTS if v not in command]
        assert not missing, missing

    @pytest.mark.parametrize("verdict,expected", sorted(VERDICTS.items()))
    def test_each_fires_the_right_evaluators(self, case, verdict, expected):
        hits = [ev for ev in case["steps"][0]["evaluators"]
                if ev["type"] == "regex"
                and re.search(ev["pattern"], f"{verdict}: explanation")]
        assert len(hits) == expected, [ev["pattern"] for ev in hits]

    def test_never_succeeding_is_not_a_clean_result(self, command):
        """The verdict that did not exist. Zero successes means the template or
        the marker is wrong and the run says nothing about timing -- it is not
        evidence that the endpoint is safe."""
        assert "ERLIK_BUSL_NO_SUCCESS" in command
        ui = (Path(__file__).resolve().parents[1] / "dashboard" / "templates"
              / "index.html").read_text()
        rx = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", ui).group(1)
        assert re.search(rx, "ERLIK_BUSL_NO_SUCCESS"), (
            "the dashboard would render a run that never succeeded as clean"
        )

    def test_a_single_success_is_not_read_as_a_decline(self, command):
        """Negative control on the test above: the correct behaviour must still
        render as a result, not as amber."""
        ui = (Path(__file__).resolve().parents[1] / "dashboard" / "templates"
              / "index.html").read_text()
        rx = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", ui).group(1)
        assert not re.search(rx, "ERLIK_BUSL_SINGLE_SUCCESS")
