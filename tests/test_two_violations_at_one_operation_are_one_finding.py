"""A second violation at one operation used to take the first one's row.

`contracts.fingerprint` drops query VALUES and keeps names, on purpose: a value is the
payload, so two SQL injection probes at `?id=1` and `?id=2` are one finding at one
operation. The cross-arm authorization checks emit one record per URL, and
`persist_findings` writes them with `INSERT OR REPLACE`. So the records collided and the
later one silently took the earlier one's row.

Measured before this fix:

    violations at /rest/order?id=1 and ?id=2  ->  1 fingerprint, 1 row, url == "?id=2"
    the 189 operations both arms of a real Juice Shop run shared
                                             ->  176 keys, 5 colliding groups,
                                                 13 urls dropped without a word,
                                                 the largest group 10 `/redirect?to=…`

Collapsing is the answer rather than distinguishing, because those ten redirect URLs ARE
one finding and ten rows would be ten times the noise. What was wrong was losing nine of
them silently. After the fix the same 189 produce 176 findings that between them NAME all
189 URLs, and the row that survives is the most canonical member rather than whichever
URL sorted last.

The sibling risk this guards is the one the commit message for the persisting change
named: "this codebase has already recorded one case where that silently replaced a
finding". The test that existed covered two differing PATHS, which never collided.
"""
from orchestrator.integrations.contracts import fingerprint
from orchestrator.integrations.inventory import MAX_URLS_NAMED, authorization_findings

TARGET = "http://app.test/"


def violations(*urls, check="object"):
    if check == "function":
        return {"refused_because": [], "findings": [
            {"url": url, "privileged": "H", "privileged_role": "admin",
             "unprivileged": "L", "unprivileged_role": "customer",
             "marker_sha256": "c5c79a1df019"} for url in urls]}
    return {"refused_because": [], "findings": [
        {"url": url, "caller": "L", "caller_subject_id": "2", "owner": "H",
         "asserted_owner": 1, "owner_field": "data.UserId"} for url in urls]}


def named_urls(finding):
    """Every URL the finding puts in front of a reader."""
    return {finding.url} | {line.strip() for line in finding.evidence.splitlines()
                            if line.strip().startswith("http")}


def test_the_premise_two_query_values_are_one_fingerprint():
    """Asserted, not assumed. Every claim below rests on this collision existing."""
    one, two = ("http://app.test/rest/order?id=1", "http://app.test/rest/order?id=2")
    rule = "erlik:authorization:object"
    assert (fingerprint(TARGET, rule, "GET", one, "", "L")
            == fingerprint(TARGET, rule, "GET", two, "", "L"))


def test_two_query_values_become_one_finding_that_names_both():
    urls = ["http://app.test/rest/order?id=1", "http://app.test/rest/order?id=2"]
    findings = authorization_findings(TARGET, "object", violations(*urls))
    assert len(findings) == 1, "one operation, one row — which is what the key can hold"
    assert named_urls(findings[0]) >= set(urls), (
        "the collapsed group must be named; a row that mentions one of two urls is the "
        "silent replacement this exists to stop")
    assert "urls that a fingerprint" in findings[0].evidence


def test_no_url_is_lost_however_many_collide():
    urls = [f"http://app.test/rest/order?id={n}" for n in range(40)]
    findings = authorization_findings(TARGET, "object", violations(*urls))
    assert len(findings) == 1
    # Bounded, because the list is built from target-supplied strings — but the count is
    # always stated, so a reader is never told about 12 when there were 40.
    assert len(named_urls(findings[0]) & set(urls)) == MAX_URLS_NAMED
    assert f"reached at {len(urls)} urls" in findings[0].evidence
    assert f"and {len(urls) - MAX_URLS_NAMED} more" in findings[0].evidence


def test_every_finding_keeps_its_own_row():
    """The fix must not over-collapse. Distinct operations stay distinct."""
    urls = ["http://app.test/rest/order?id=1", "http://app.test/rest/basket/1",
            "http://app.test/api/Users", "http://app.test/rest/order?id=2"]
    findings = authorization_findings(TARGET, "object", violations(*urls))
    assert len(findings) == 3
    assert len({f.fingerprint for f in findings}) == 3, "one row each, no collision left"
    everything = set().union(*(named_urls(f) for f in findings))
    assert everything >= set(urls), "and still nothing lost"


def test_the_surviving_url_is_the_canonical_one():
    """Not whichever sorted last, which is what `INSERT OR REPLACE` used to decide.

    `canonicality` is the rule the duplicate-response pruner already uses: fewest odd
    segments, then shortest. `/` beats `/#/photo-wall` — a real pair from the Juice Shop
    run, where a fragment makes two URLs one operation.
    """
    findings = authorization_findings(TARGET, "object", violations(
        "http://app.test/#/photo-wall", "http://app.test/"))
    assert len(findings) == 1
    assert findings[0].url == "http://app.test/"


def test_both_checks_collapse():
    """The function-level check shares the key and so shares the defect."""
    findings = authorization_findings(TARGET, "function", violations(
        "http://app.test/api/Users?page=1", "http://app.test/api/Users?page=2",
        check="function"))
    assert len(findings) == 1
    assert len(named_urls(findings[0])) == 2
