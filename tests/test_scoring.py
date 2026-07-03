"""Characterization tests for the ground-truth scoring instruments.

These pin the exact behaviour of the two functions every thesis coverage /
precision number is derived from:

    * _match_finding_to_ground_truth_scored  (main.py ~5909)
    * _sound_confusion_matrix                (main.py ~6009)

A change that moves any assertion here moves a number in the paper, so the
suite is intentionally explicit about *why* each score comes out the way it
does (type=1, url=1, param=1, evidence=1; generic url/param give 0.5 each;
threshold for a true positive is score >= 2.0).
"""

import orchestrator.main as m


# ── helpers ──────────────────────────────────────────────────────────────
def gt(vuln_type, url_pattern="", parameter=""):
    """Build a ground-truth row in the real seeded schema."""
    return {
        "target_name": "OWASP Juice Shop",
        "target_url": "http://localhost:3000",
        "vuln_type": vuln_type,
        "severity": "high",
        "url_pattern": url_pattern,
        "parameter": parameter,
    }


def finding(vuln_type, url="", parameter="", evidence=""):
    return {"vuln_type": vuln_type, "url": url, "parameter": parameter,
            "evidence": evidence}


def score_of(f, gts):
    return m._match_finding_to_ground_truth_scored(f, gts)


# ── _match_finding_to_ground_truth_scored ────────────────────────────────
class TestScoredMatcher:
    def test_strong_match_scores_four(self):
        """type + url + param + evidence all hit -> score 4.0, matched."""
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/products/search?q=1",
                    parameter="q",
                    evidence="boolean-based blind, back-end DBMS: SQLite")
        r = score_of(f, [gt("SQL Injection", "/rest/products/search", "q")])
        assert r["match"] is True
        assert r["score"] == 4.0
        assert r["gt_index"] == 0

    def test_type_only_is_below_threshold(self):
        """Specific GT + finding that only shares the type -> score 1.0, no match.

        (url_pattern present but unmatched = 0, param present but unmatched = 0,
        no evidence keyword.)
        """
        f = finding("SQL Injection")  # empty url/param/evidence
        r = score_of(f, [gt("SQL Injection", "/rest/products/search", "q")])
        assert r["match"] is False
        assert r["score"] == 1.0
        assert r["gt_index"] == -1

    def test_generic_gt_matches_on_type_plus_two_half_credits(self):
        """A GT with no url_pattern and no parameter awards 0.5 + 0.5, so a
        bare type-only finding reaches exactly the 2.0 threshold.

        This is a deliberate, load-bearing property of the scorer (server-wide
        issues like CORS/headers have no url_pattern). Locked so a refactor
        cannot silently change coverage for generic vulns.
        """
        f = finding("Broken Access Control")  # no evidence keyword in the name
        r = score_of(f, [gt("Broken Access Control")])  # generic GT
        assert r["match"] is True
        assert r["score"] == 2.0

    def test_alias_matches_short_form(self):
        """'SQLi' matches the 'SQL Injection' GT via the alias table."""
        f = finding("SQLi",
                    url="http://localhost:3000/rest/products/search",
                    parameter="q",
                    evidence="union select")
        r = score_of(f, [gt("SQL Injection", "/rest/products/search", "q")])
        assert r["match"] is True
        assert r["gt_index"] == 0

    def test_evidence_keyword_pushes_over_threshold(self):
        """Specific GT whose url/param don't match, but an evidence keyword
        confirms it: type(1) + evidence(1) = 2.0 -> match."""
        f = finding("XSS", evidence="alert( fired, reflected payload")
        r = score_of(f, [gt("XSS", "/rest/products/search", "q")])
        assert r["match"] is True
        assert r["score"] == 2.0

    def test_score_one_point_five_is_below_threshold(self):
        """type(1) + unmatched specific url(0) + generic param(0.5) + no
        evidence keyword = 1.5 -> no match. Boundary just under 2.0.

        (Security Misconfiguration is used because none of its evidence
        keywords appear inside its own type name.)
        """
        f = finding("Security Misconfiguration")
        r = score_of(f, [gt("Security Misconfiguration", "/admin")])
        assert r["match"] is False
        assert r["score"] == 1.5

    def test_no_type_match_returns_no_match(self):
        f = finding("Clickjacking", evidence="X-Frame-Options missing")
        r = score_of(f, [gt("SQL Injection", "/rest/products/search", "q")])
        assert r["match"] is False
        assert r["score"] == 0
        assert r["gt_index"] == -1
        assert "No type match" in r["reason"]

    def test_empty_ground_truth_list(self):
        r = score_of(finding("SQL Injection", evidence="union"), [])
        assert r["match"] is False
        assert r["score"] == 0
        assert r["gt_index"] == -1

    def test_best_gt_is_selected_among_many(self):
        """With several GTs of the same type, the highest-scoring one wins."""
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/user/login",
                    parameter="email",
                    evidence="' OR 1=1-- returned a token")
        gts = [
            gt("SQL Injection", "/rest/products/search", "q"),  # weak: url/param mismatch
            gt("SQL Injection", "/rest/user/login", "email"),   # strong: exact
        ]
        r = score_of(f, gts)
        assert r["match"] is True
        assert r["gt_index"] == 1

    def test_bool_wrapper_agrees_with_scored(self):
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/products/search",
                    parameter="q", evidence="union")
        gts = [gt("SQL Injection", "/rest/products/search", "q")]
        assert m._match_finding_to_ground_truth(f, gts) is True
        assert m._match_finding_to_ground_truth(finding("SQL Injection"), gts) is False


# ── _sound_confusion_matrix ──────────────────────────────────────────────
class TestSoundConfusionMatrix:
    def test_single_perfect_match(self):
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/products/search",
                    parameter="q", evidence="union boolean-based")
        r = m._sound_confusion_matrix([f], [gt("SQL Injection", "/rest/products/search", "q")])
        assert (r["tp"], r["fp"], r["fn"]) == (1, 0, 0)
        assert r["precision"] == 1.0
        assert r["recall"] == 1.0
        assert r["f1"] == 1.0

    def test_duplicate_findings_count_as_false_positive(self):
        """One-to-one greedy assignment: a second detection of the SAME vuln
        cannot be matched to the already-used GT, so it is an FP. This is the
        'honest' property that distinguishes the sound matrix from the legacy
        fuzzy scorer (which let one finding satisfy many GTs)."""
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/products/search",
                    parameter="q", evidence="union")
        r = m._sound_confusion_matrix([f, dict(f)],
                                      [gt("SQL Injection", "/rest/products/search", "q")])
        assert (r["tp"], r["fp"], r["fn"]) == (1, 1, 0)
        assert r["precision"] == 0.5
        assert r["recall"] == 1.0
        assert r["f1"] == 0.6667

    def test_unmatched_finding_and_unmatched_gt(self):
        """A finding with no GT match is an FP; a GT with no finding is an FN."""
        r = m._sound_confusion_matrix(
            [finding("Clickjacking", evidence="x-frame-options")],
            [gt("SQL Injection", "/rest/products/search", "q")],
        )
        assert (r["tp"], r["fp"], r["fn"]) == (0, 1, 1)
        assert r["precision"] == 0.0
        assert r["recall"] == 0.0
        assert r["f1"] == 0.0

    def test_empty_inputs_do_not_divide_by_zero(self):
        r = m._sound_confusion_matrix([], [])
        assert (r["tp"], r["fp"], r["fn"]) == (0, 0, 0)
        assert r["precision"] == 0.0
        assert r["recall"] == 0.0
        assert r["f1"] == 0.0

    def test_two_distinct_matches(self):
        sqli = finding("SQL Injection",
                       url="http://localhost:3000/rest/products/search",
                       parameter="q", evidence="union")
        xss = finding("XSS",
                      url="http://localhost:3000/rest/products/search",
                      parameter="q", evidence="reflected alert(")
        gts = [gt("SQL Injection", "/rest/products/search", "q"),
               gt("XSS", "/rest/products/search", "q")]
        r = m._sound_confusion_matrix([sqli, xss], gts)
        assert (r["tp"], r["fp"], r["fn"]) == (2, 0, 0)
        assert r["precision"] == 1.0
        assert r["recall"] == 1.0


# ── real seeded ground truth (guards the thesis denominator) ─────────────
class TestSeededGroundTruth:
    def test_juice_shop_ground_truth_count_is_stable(self):
        """The recall denominator the whole thesis reports against. If this
        count changes, every coverage figure (X / N) changes with it."""
        assert len(m.JUICE_SHOP_GROUND_TRUTH) == 35

    def test_every_gt_row_has_required_matcher_keys(self):
        for row in m.JUICE_SHOP_GROUND_TRUTH:
            assert row["vuln_type"]           # accessed as gt["vuln_type"]
            assert "url_pattern" in row       # accessed via .get()
            assert "parameter" in row

    def test_realistic_finding_matches_expected_gt(self):
        """End-to-end: a sqlmap-shaped finding matches the search-SQLi GT in
        the real 35-item list (not a hand-made single-element list)."""
        f = finding("SQL Injection",
                    url="http://localhost:3000/rest/products/search?q=1",
                    parameter="q",
                    evidence="back-end DBMS: SQLite, boolean-based blind")
        r = score_of(f, m.JUICE_SHOP_GROUND_TRUTH)
        assert r["match"] is True
        matched = m.JUICE_SHOP_GROUND_TRUTH[r["gt_index"]]
        assert matched["url_pattern"] == "/rest/products/search"


# ── reasoning-model <think> stripping (perf + parser correctness) ─────────
class TestStripReasoning:
    def test_closed_think_block_removed(self):
        r = m._strip_reasoning('<think>reasoning here</think>{"action":"done"}')
        assert r == '{"action":"done"}'

    def test_unclosed_think_tail_dropped(self):
        assert m._strip_reasoning('answer<think>cut off') == 'answer'

    def test_no_think_untouched(self):
        assert m._strip_reasoning('{"action":"run_tool"}') == '{"action":"run_tool"}'

    def test_case_insensitive(self):
        assert m._strip_reasoning('<THINK>x</THINK>ok') == 'ok'
