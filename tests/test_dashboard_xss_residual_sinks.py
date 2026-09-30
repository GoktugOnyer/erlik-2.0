"""Residual stored-XSS sinks in the dashboard, closed after the DOMPurify pass.

THREAT MODEL (same as test_dashboard_injection.py). The dashboard origin can
launch attacks, read every engagement, and reach the API, so script execution
there is a privilege boundary crossed. The primary markdown sink was already
closed (marked.parse -> DOMPurify.sanitize in renderMarkdown). These guard the
three sinks that still interpolated attacker- or model-influenced data straight
into innerHTML:

  1. The session-list row wrote ``s.target_url`` raw into both the ``title``
     attribute and the row text. Scope enforcement only checks the HOST, so an
     in-scope URL can still carry a payload in its path/query
     (``http://inscope.host/"><img src=x onerror=...>``) and it executes in any
     operator's browser that opens the sessions list — stored, cross-operator.
  2. The benchmark comparison table joined ``vuln_types_found`` (model-authored
     strings) raw into a cell.
  3. The benchmark-history list wrote ``b.target_name``/``b.target_url`` raw.

Each test asserts BOTH that the escaped form is present AND that the exact
pre-fix raw form is absent. The second assertion is the mutation guard: revert
any fix and the raw sink returns, failing the test.
"""

import pathlib

import pytest

UI = (pathlib.Path(__file__).resolve().parents[1]
      / "dashboard" / "templates" / "index.html")


@pytest.fixture(scope="module")
def src():
    return UI.read_text()


class TestSessionListTargetUrl:
    def test_target_url_is_escaped_in_attribute_and_text(self, src):
        assert 'title="${escapeHtml(s.target_url || \'\')}"' in src, \
            "session-list target_url title= is not escaped"
        assert "${escapeHtml(s.target_url || '---')}" in src, \
            "session-list target_url text is not escaped"

    def test_the_raw_sink_is_gone(self, src):
        # Exact pre-fix shape. If it returns, the fix was reverted.
        assert 'title="${s.target_url || \'\'}">${s.target_url || \'---\'}' not in src


class TestBenchmarkVulnTypes:
    def test_each_vuln_type_is_escaped_before_join(self, src):
        for var in ("cold", "warm", "chain"):
            assert f"({var}.vuln_types_found || []).map(escapeHtml).join(', ')" in src, \
                f"{var}.vuln_types_found is joined without escaping each element"

    def test_the_raw_join_is_gone(self, src):
        for var in ("cold", "warm", "chain"):
            assert f"({var}.vuln_types_found || []).join(', ')" not in src


class TestBenchmarkHistoryTarget:
    def test_target_name_or_url_is_escaped(self, src):
        assert "${escapeHtml(b.target_name || b.target_url || '')}" in src, \
            "benchmark-history target is not escaped"

    def test_the_raw_sink_is_gone(self, src):
        assert "${b.target_name || b.target_url}" not in src


class TestMarkdownSanitizer:
    def test_renderMarkdown_sanitizes_marked_output(self, src):
        """renderMarkdown must pass marked.parse() output through
        DOMPurify.sanitize before it reaches innerHTML. Removing sanitize
        (returning the raw parsed html) must fail this."""
        body = src[src.index("function renderMarkdown"):]
        body = body[:body.index("\n        }")]
        assert "marked.parse(" in body
        assert "DOMPurify.sanitize(" in body, \
            "renderMarkdown no longer sanitizes marked.parse output"


class TestGuardIsNotVacuous:
    def test_escapeHtml_exists_and_covers_the_five_html_metacharacters(self, src):
        block = src[src.index("function escapeHtml"):src.index("function escapeHtml") + 400]
        for ch in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            assert ch in block, f"escapeHtml no longer emits {ch}"

    def test_escapeHtml_is_used_widely(self, src):
        # If escapeHtml vanished, the 'escaped form present' assertions above
        # would pass vacuously against a file that simply stopped calling it.
        assert src.count("escapeHtml(") > 10, "escapeHtml is barely used — check the sinks"
