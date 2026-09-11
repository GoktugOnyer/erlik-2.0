"""The one finding producer that is not a stage was the one with no redaction.

`adapters`, `interactsh` and `deterministic` all build evidence as
`safe_evidence(redact(text, ctx.known))[:MAX_EVIDENCE_CHARS]`. The cross-arm checks are
asked for on demand rather than run as a stage, so they never had a `JobContext` — and so
they had no `known` set, called neither function, and quoted discovery's URLs straight
into a DefectDojo description whose banner reads "Evidence (credentials redacted)".

THE REALISTIC LEAK IS NOT A PLANTED ONE. An application that puts a session token in a
link is committing an ordinary, reportable bug; katana follows the link, the URL lands in
an endpoint row, and the token travels into the export as the finding's own `endpoints`
value. Measured before this fix: a URL carrying a JWT reached `IntegrationFinding.url`
verbatim, while `redact()` on the same string yields `?token=[REDACTED]`.

WHAT WAS ALREADY SAFE, and is asserted here so a future change cannot quietly remove it:
the target-supplied `asserted_owner` is interpolated with `!r`, which escapes a bidi
override into `\\u202e` rather than applying it. That is load-bearing and accidental —
`repr` was chosen to show the value's type — so it gets a test.

`basis` is deliberately exempt. It is lane-authored prose, which is the distinction
`IntegrationFinding.evidence` documents: evidence is target-controlled and always needs
care, basis never does.
"""
import pytest

from orchestrator.integrations.contracts import MAX_EVIDENCE_CHARS
from orchestrator.integrations.inventory import _arm_secrets, authorization_findings
from orchestrator.integrations.security import SecretStore

TARGET = "http://app.test/"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s3cr3tsignaturevalue"


def object_result(url, asserted_owner="1", caller="L", owner="H"):
    return {"refused_because": [], "findings": [{
        "url": url, "caller": caller, "caller_subject_id": "2", "owner": owner,
        "asserted_owner": asserted_owner, "owner_field": "data.UserId"}]}


# -------------------------------------------------------------- the url is redacted

def test_a_token_in_a_discovered_url_does_not_reach_the_finding():
    url = f"http://app.test/rest/basket/2?token={JWT}"
    finding = authorization_findings(TARGET, "object", object_result(url))[0]
    assert JWT not in finding.url
    assert "[REDACTED]" in finding.url
    assert finding.url.startswith("http://app.test/rest/basket/2?token=")


def test_a_collapsed_group_has_every_url_redacted():
    """The names in the evidence list go through the same call, not a second path."""
    findings = authorization_findings(TARGET, "object", {
        "refused_because": [], "findings": [
            {"url": f"http://app.test/rest/order?id=1&token={JWT}", "caller": "L",
             "caller_subject_id": "2", "owner": "H", "asserted_owner": "1",
             "owner_field": "data.UserId"},
            {"url": f"http://app.test/rest/order?id=2&token={JWT}", "caller": "L",
             "caller_subject_id": "2", "owner": "H", "asserted_owner": "1",
             "owner_field": "data.UserId"}]})
    assert len(findings) == 1
    assert JWT not in findings[0].url + findings[0].evidence
    assert findings[0].evidence.count("[REDACTED]") == 2, "both urls, not just the survivor"


def test_the_fingerprint_is_unchanged_by_redaction():
    """Redaction is for display. A key that moved when a token changed would orphan
    every finding already exported — and `fingerprint` drops query values anyway, which
    is why the raw URL is what it hashes."""
    plain = authorization_findings(TARGET, "object", object_result(
        "http://app.test/rest/basket/2?token=aaaa"))[0]
    other = authorization_findings(TARGET, "object", object_result(
        "http://app.test/rest/basket/2?token=bbbb"))[0]
    assert plain.fingerprint == other.fingerprint


# ------------------------------------------- and against the arms' own secret values

def test_an_arm_session_cookie_in_a_url_is_redacted(tmp_path, monkeypatch):
    """The case `redact`'s header rules cannot reach: an opaque value, in a query.

    Every other producer redacts against the identities in play. This path had no such
    set at all, so an arm's own session value in a discovered link was published.
    """
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path))
    secret = "7f4c1b9e22a84d6fa0e3"
    arm = SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                             "cookies": [{"name": "sid", "value": secret}]})
    result = object_result(f"http://app.test/rest/basket/2?sid={secret}", caller=arm)
    assert secret in _arm_secrets(result), "the arm's declaration is what supplies it"
    finding = authorization_findings(TARGET, "object", result)[0]
    assert secret not in finding.url
    assert "[REDACTED]" in finding.url


def test_an_unreadable_arm_costs_a_value_not_a_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path))
    result = object_result("http://app.test/rest/basket/2", caller="not-a-secret-handle")
    assert _arm_secrets(result) == ()
    assert len(authorization_findings(TARGET, "object", result)) == 1


# ----------------------------------------------------------- evidence stays quotable

def test_target_bytes_in_the_owner_value_cannot_reorder_the_line():
    """Load-bearing and accidental: `!r` is what makes this true today."""
    finding = authorization_findings(TARGET, "object", object_result(
        "http://app.test/rest/basket/2", asserted_owner="4‮admin​"))[0]
    assert "‮" not in finding.evidence
    assert "‮" not in finding.title


def test_a_declared_role_cannot_reorder_the_title():
    """A role is operator text, and `looks_injectable` rejects newlines but not bidi —
    and the role is interpolated into the title unquoted, where `!r` does not protect it.
    """
    finding = authorization_findings(TARGET, "function", {
        "refused_because": [], "findings": [{
            "url": "http://app.test/api/Users", "privileged": "H",
            "privileged_role": "admin", "unprivileged": "L",
            "unprivileged_role": "cust‮omer", "marker_sha256": "c5c79a1df019"}]})[0]
    assert "‮" not in finding.title
    assert "‮" not in finding.evidence
    assert "<U+202E>" in finding.title, "named in place, not deleted"


def test_the_evidence_is_bounded():
    urls = [f"http://app.test/rest/order?id={'9' * 200}{n}" for n in range(12)]
    finding = authorization_findings(TARGET, "object", {
        "refused_because": [], "findings": [
            {"url": url, "caller": "L", "caller_subject_id": "2", "owner": "H",
             "asserted_owner": "1", "owner_field": "data.UserId"} for url in urls]})[0]
    assert len(finding.evidence) <= MAX_EVIDENCE_CHARS


def test_the_bound_has_one_definition():
    """It was three copies of 1500 and a fourth was about to be written."""
    from orchestrator.integrations import adapters, deterministic, interactsh
    assert (adapters.MAX_EVIDENCE_CHARS is interactsh.MAX_EVIDENCE_CHARS
            is deterministic.MAX_EVIDENCE_CHARS is MAX_EVIDENCE_CHARS)


def test_basis_is_not_redacted():
    """Stated, because a future reader will wonder why only two of three strings are."""
    finding = authorization_findings(TARGET, "object", object_result(
        "http://app.test/rest/basket/2"))[0]
    assert "Identity.subject_id" in finding.basis, (
        "lane-authored prose, and redaction would corrupt it for no gain")
