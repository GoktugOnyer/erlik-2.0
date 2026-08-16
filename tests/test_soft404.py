"""Per-target catch-all measurement, replacing a hardcoded 3748.

3748 is OWASP Juice Shop's catch-all body size. It was hardcoded in five prompt
sites, and all 39 recorded gobuster invocations carry it — so a soft-404 control
already ran universally at the tool boundary, calibrated to the wrong app
everywhere except one.

NOT built here: soft-404 SUPPRESSION of findings. Measured against the recorded
corpus, all 60 `Content discovery:` rows score as TRUE positives, so suppressing
them lowers precision (0.903 -> 0.865) and costs recall on GT #23. Suppressing a
true positive lowers precision whenever precision < 1. Only the measurement
survives, and `test_findings_match_ground_truth` in test_auto_detect.py is
untouched by this change.
"""

import pytest

from orchestrator import soft404 as S
from orchestrator.main import _discovery_filter


def samples(*triples):
    return [S.Sample(p, st, ln) for p, st, ln in triples]


@pytest.fixture(autouse=True)
def _clear():
    S.reset_cache()
    yield
    S.reset_cache()


class TestClassify:
    """Pure state machine — no network, so every branch is reachable."""

    def test_catchall_when_every_probe_is_200_at_one_size(self):
        v = S.classify(samples(("/a", 200, 3748), ("/b", 200, 3748),
                               ("/c", 200, 3748), ("/d", 200, 3748)))
        assert v.state == S.CATCHALL and v.size == 3748 and v.confident

    def test_honest_404(self):
        v = S.classify(samples(("/a", 404, 120), ("/b", 404, 118),
                               ("/c", 404, 120), ("/d", 410, 90)))
        assert v.state == S.HONEST_404 and v.size is None and v.confident

    def test_indeterminate_on_mixed_statuses(self):
        v = S.classify(samples(("/a", 200, 3748), ("/b", 404, 120)))
        assert v.state == S.INDETERMINATE and not v.confident

    def test_indeterminate_when_200s_differ_in_size(self):
        """A catch-all whose size varies cannot be filtered on — guessing a
        size silently suppresses real pages of that size."""
        v = S.classify(samples(("/a", 200, 3748), ("/b", 200, 3751)))
        assert v.state == S.INDETERMINATE

    def test_indeterminate_with_too_few_probes(self):
        assert S.classify(samples(("/a", 200, 10))).state == S.INDETERMINATE
        assert S.classify([]).state == S.INDETERMINATE

    def test_redirect_catchall_counts(self):
        v = S.classify(samples(("/a", 302, 0), ("/b", 302, 0)))
        assert v.state == S.CATCHALL and v.size == 0


class TestTwinStability:
    def test_agreeing_rounds_pass_through(self):
        a = S.Verdict(S.CATCHALL, 3748)
        assert S.agree(a, S.Verdict(S.CATCHALL, 3748)).state == S.CATCHALL

    def test_disagreeing_state_is_indeterminate(self):
        assert S.agree(S.Verdict(S.CATCHALL, 3748),
                       S.Verdict(S.HONEST_404)).state == S.INDETERMINATE

    def test_disagreeing_size_is_indeterminate(self):
        """A wrong catch-all size is worse than no filter."""
        assert S.agree(S.Verdict(S.CATCHALL, 3748),
                       S.Verdict(S.CATCHALL, 4102)).state == S.INDETERMINATE


class TestFlagRendering:
    def test_catchall_uses_the_measured_size(self):
        assert S.filter_flag(S.Verdict(S.CATCHALL, 91234)) == "--exclude-length 91234"
        assert S.filter_flag(S.Verdict(S.CATCHALL, 91234), "ffuf") == "-fs 91234"

    def test_honest_404_omits_the_flag_entirely(self):
        """Negative control. On a host with a real 404 the flag filters nothing
        — and can suppress a genuine page that happens to be that size."""
        assert S.filter_flag(S.Verdict(S.HONEST_404)) == ""
        assert S.filter_flag(S.Verdict(S.HONEST_404), "ffuf") == ""

    @pytest.mark.parametrize("verdict", [None, S.Verdict(S.INDETERMINATE)])
    def test_unknown_renders_byte_identically_to_the_old_literal(self, verdict):
        """The equivalence control: wherever the probe cannot answer
        confidently, erlik emits exactly what it emitted before this module."""
        assert S.filter_flag(verdict) == "--exclude-length 3748"
        assert S.filter_flag(verdict, "ffuf") == "-fs 3748"


class TestPromptSubstitution:
    def test_unprobed_target_matches_legacy_output(self):
        assert _discovery_filter("http://juice-shop:3000") == "--exclude-length 3748"
        assert _discovery_filter("http://juice-shop:3000", "ffuf") == "-fs 3748"

    def test_measured_target_uses_its_own_size(self):
        S.remember("http://client-app:8080", S.Verdict(S.CATCHALL, 91234))
        assert _discovery_filter("http://client-app:8080") == "--exclude-length 91234"
        # ...and a different target is unaffected
        assert _discovery_filter("http://other:8080") == "--exclude-length 3748"

    def test_honest_404_target_drops_the_flag(self):
        S.remember("http://clean:8080", S.Verdict(S.HONEST_404))
        assert _discovery_filter("http://clean:8080") == ""

    def test_no_hardcoded_size_is_emitted_into_a_command(self):
        """Five sites rendered the literal into a command string. The value now
        comes from the probe.

        Inspects STRING LITERALS that build a discovery command, not raw source
        text — the module docstring and two code comments explain the old
        constant, and a naive grep would make this test fail for documenting
        itself.
        """
        import ast
        import re
        import tokenize
        from pathlib import Path

        src = Path(__file__).resolve().parents[1] / "orchestrator" / "main.py"
        text = src.read_text()

        # Docstrings explain the old constant on purpose; they are not emitted.
        doc_lines: set[int] = set()
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", None)
            if not body:
                continue
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                doc_lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))

        # Line-based, NOT token-based. On Python 3.12+ an f-string tokenizes as
        # FSTRING_START/MIDDLE/END rather than a single STRING token, so a
        # token scan for STRING skips exactly the command templates this is
        # meant to check — verified blind against a synthetic regression before
        # this was rewritten.
        offenders = []
        for n, line in enumerate(text.splitlines(), 1):
            if n in doc_lines or line.lstrip().startswith("#"):
                continue
            if "gobuster" not in line and "ffuf" not in line:
                continue
            if re.search(r"(?:--exclude-length|-fs)\s+\d+", line):
                offenders.append(f"line {n}: {line.strip()[:80]}")
        assert offenders == [], (
            "a discovery command template carries a hardcoded size again: "
            + "; ".join(offenders))

    def test_the_check_above_can_actually_fail(self, tmp_path):
        """Guard on the guard, run against a synthetic regression.

        The first version of the check used a STRING-token scan and was BLIND:
        on Python 3.12+ f-strings tokenize as FSTRING_MIDDLE, so it skipped
        every real command template while still passing. A check that inspects
        nothing is the exact defect class this project keeps shipping, so it
        gets its own control.
        """
        import ast
        import re

        bad = tmp_path / "regressed.py"
        bad.write_text(
            'def f(t):\n'
            '    """Docstring mentioning gobuster --exclude-length 3748 harmlessly."""\n'
            '    # a comment with ffuf -fs 3748 in it\n'
            "    return f'gobuster dir -u {t} -w /w.txt --exclude-length 3748'\n"
        )
        text = bad.read_text()
        doc_lines: set[int] = set()
        for node in ast.walk(ast.parse(text)):
            body = getattr(node, "body", None)
            if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)) or not body:
                continue
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                doc_lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))

        offenders = []
        for n, line in enumerate(text.splitlines(), 1):
            if n in doc_lines or line.lstrip().startswith("#"):
                continue
            if "gobuster" not in line and "ffuf" not in line:
                continue
            if re.search(r"(?:--exclude-length|-fs)\s+\d+", line):
                offenders.append(n)

        assert offenders == [4], (
            f"the guard missed a real f-string regression (found {offenders}); "
            f"it must ignore the docstring on line 2 and the comment on line 3")

    def test_legacy_constant_lives_in_exactly_one_place(self):
        assert S.LEGACY_SIZE == 3748


class TestProbeNeverBreaksASession:
    @pytest.mark.parametrize("target", ["", "not a url", "http://", "http://a[b].com/"])
    def test_unusable_target_is_indeterminate_not_an_exception(self, target):
        import asyncio
        v = asyncio.run(S.probe_origin(target))
        assert v.state == S.INDETERMINATE

    def test_unreachable_host_is_indeterminate(self):
        """A target that cannot be probed keeps erlik's existing behaviour
        rather than degrading it."""
        import asyncio

        class Boom:
            async def get(self, *a, **k):
                raise OSError("connection refused")
            async def aclose(self):
                pass

        v = asyncio.run(S.probe_origin("http://nope.invalid:9/", client=Boom()))
        assert v.state == S.INDETERMINATE

    def test_stable_catchall_host_is_measured(self):
        import asyncio

        class Fake:
            async def get(self, url):
                class R:
                    status_code = 200
                    content = b"x" * 4096
                return R()
            async def aclose(self):
                pass

        v = asyncio.run(S.probe_origin("http://cat:8080/", client=Fake()))
        assert v.state == S.CATCHALL and v.size == 4096
        # cached for the prompt renderer
        assert _discovery_filter("http://cat:8080/") == "--exclude-length 4096"

    def test_unstable_host_is_indeterminate(self):
        import asyncio

        class Flaky:
            def __init__(self):
                self.n = 0

            async def get(self, url):
                self.n += 1
                class R:
                    status_code = 200
                    content = b"x" * (4096 if self.n <= 4 else 5000)
                return R()

            async def aclose(self):
                pass

        v = asyncio.run(S.probe_origin("http://flaky:8080/", client=Flaky()))
        assert v.state == S.INDETERMINATE
        assert _discovery_filter("http://flaky:8080/") == "--exclude-length 3748"
