"""The R0 gate: two identities must discover the SAME operation set.

§3 of docs/future-plan.md moved "identity isolation demonstrated" out of R1 and
into R0's exit gate, for a measured reason. A differential run on 2026-09-10
reported nine findings against a vulnerable DVWA security level and one against a
hardened one, and the result was unusable: the two arms shared ONE of eight
`(url, parameter)` pairs. E-008 states the requirement outright —

    Two identities testing the same operation must produce the same operation
    set — a differential whose arms discovered different URLs is not a
    differential, and a run that proves this by comparing arm surfaces is the
    demonstration R0 needs.

These tests are the comparison, and they are written against the REAL shape of
the divergence rather than a paraphrase of it. Measured on DVWA, same session,
only the `security` cookie changed:

    low         controls: id (text), Submit (submit)
    impossible  controls: id (text), Submit (submit), user_token (hidden)

`form_endpoint` puts companion NAME=VALUE pairs into the URL query, so the
hardened arm's URL carries a token whose value changes on every observation, and
the two arms produce different strings for one form.

Why the value must not be persisted at all, rather than refreshed: DVWA's token
is SINGLE-USE, and a consumed one is answered with ZERO BYTES.

    fresh token, first use -> 4757 bytes, "First name: admin"
    the same token again   -> 0 bytes
    no token at all        -> 389 bytes (a PHP warning page)

curl exits 0 on an empty body, which is how 156 of 208 injection steps on the
hardened arm came back empty and the stage still reported `completed`. Carrying a
volatile value is strictly worse than omitting it: it turns a response that can
be reasoned about into nothing at all.
"""
import json

import pytest

from orchestrator.integrations.contracts import form_endpoint, operation_key


def op(built, method="GET"):
    """The operation a form_endpoint result belongs to."""
    url, testable = built
    return operation_key(url, method, testable)


def form(*controls, action="http://app.test/vulnerabilities/sqli/", method="GET"):
    return {"method": method, "action": action,
            "controls": [dict(zip(("name", "type", "value"), c)) for c in controls]}


LOW = (("id", "text", ""), ("Submit", "submit", "Submit"))


def hardened(token):
    return (("id", "text", ""), ("Submit", "submit", "Submit"),
            ("user_token", "hidden", token))


# --------------------------------------------------------------- the gate

def test_two_observations_of_one_form_are_one_operation():
    """The same form, observed twice, must not become two operations.

    This is the whole gate in miniature. DVWA hands out a fresh `user_token` on
    every GET of the same page, so two observations differ in nothing that
    matters and everything that is compared.
    """
    first = form_endpoint(form(*hardened("03f872e49853c221909ffdae5f1a64a4")), "http://app.test/")
    second = form_endpoint(form(*hardened("a88596570d056afa1266678400964e14")), "http://app.test/")
    assert first is not None and second is not None
    # The OBSERVATIONS differ, and should: each carries the token it was served.
    assert first[0] != second[0]
    # The OPERATION must not.
    assert op(first) == op(second), (
        "two observations of one form produced two different operations:\n"
        f"  {op(first)}\n  {op(second)}\n"
        "a volatile companion value is in the operation's identity")


def test_the_two_dvwa_arms_agree_on_the_operation_set():
    """The measured divergence, as a test.

    At `low` the form has no token; at `impossible` it has one. The testable
    surface — what a case can inject into — is `id` in both arms, so both arms
    must report the same operation.
    """
    low = form_endpoint(form(*LOW), "http://app.test/")
    imp = form_endpoint(form(*hardened("b3ae1ff6aafb9151ef0c06930815107d")), "http://app.test/")
    assert low is not None and imp is not None
    assert op(low) == op(imp), (
        "the vulnerable and hardened arms describe the same form differently:\n"
        f"  low         {op(low)}   from {low[0]}\n"
        f"  impossible  {op(imp)}   from {imp[0]}\n"
        "so a differential between them compares two surfaces, not one variable")


# ------------------------------------------------- what must still NOT merge

def test_a_stable_companion_is_still_carried():
    """The companion query exists for a reason and must not be thrown away.

    DVWA's SQLi page answers `?id=<payload>` with nothing and
    `?id=<payload>&Submit=Submit` with the rows. Dropping stable companions to
    make the arms agree would trade a false difference for a probe that cannot
    reach the handler — an input discovered and untestable, reported as tested.
    """
    url, testable = form_endpoint(form(*LOW), "http://app.test/")
    assert "Submit=Submit" in url, f"the submit control was dropped from {url}"
    assert testable == ["id"]


def test_method_still_separates_operations():
    """E-007: "Do not merge different methods." A POST form's controls are BODY
    parameters, and form_endpoint declines it outright."""
    assert form_endpoint(form(*LOW, method="POST"), "http://app.test/") is None


def test_a_different_testable_surface_is_a_different_operation():
    """Absorbing volatile companions must not absorb anything else.

    Two forms on the same path with different injectable inputs are different
    operations, and a normalisation that merged them would hide one of them.
    """
    one = form_endpoint(form(("id", "text", ""), ("Submit", "submit", "Submit")), "http://app.test/")
    two = form_endpoint(form(("name", "text", ""), ("Submit", "submit", "Submit")), "http://app.test/")
    assert op(one) != op(two), "two different injectable surfaces collapsed into one operation"


def test_a_path_still_separates_operations():
    one = form_endpoint(form(*LOW, action="http://app.test/a/"), "http://app.test/")
    two = form_endpoint(form(*LOW, action="http://app.test/b/"), "http://app.test/")
    assert op(one) != op(two)


# ------------------------------------------- the operation key on its own

def test_overlapping_discoveries_resolve_to_one_operation():
    """E-007: "overlapping Katana/ZAP/schema discoveries resolve to one operation
    where appropriate".

    The same search input reaches the inventory three ways — crawled with a
    sample value in the query, synthesised from its GET form with the submit
    control in the query, and named by a schema with no query at all. All three
    are one operation, and before this key they were three unrelated rows.
    """
    crawled = operation_key("http://app.test/search?q=hello", "GET", ["q"])
    from_form = operation_key("http://app.test/search?Submit=Submit", "GET", ["q"])
    from_schema = operation_key("http://app.test/search", "GET", ["q"])
    assert crawled == from_form == from_schema, (
        f"\n  crawled     {crawled}\n  form        {from_form}\n  schema      {from_schema}")


def test_get_and_post_are_never_one_operation():
    """E-007: "Do not merge different methods"."""
    assert (operation_key("http://app.test/items", "GET", ["id"])
            != operation_key("http://app.test/items", "POST", ["id"]))


def test_discovery_order_is_not_part_of_the_operation():
    """Two arms need not enumerate a form's inputs in the same order, and an
    operation that depended on that order would fork for no reason."""
    assert (operation_key("http://app.test/x", "GET", ["b", "a"])
            == operation_key("http://app.test/x", "GET", ["a", "b"]))
    assert (operation_key("http://app.test/x", "GET", ["a", "a", "b"])
            == operation_key("http://app.test/x", "GET", ["a", "b"]))


def test_a_fragment_and_a_default_port_do_not_fork_the_operation():
    """E-007 asks for normalisation of query order, fragments and path
    parameters. A fragment is never sent to the server at all."""
    assert (operation_key("http://app.test/x#section", "GET", ["a"])
            == operation_key("http://app.test/x", "GET", ["a"]))
    # The port is made EXPLICIT rather than stripped, which is what
    # canonical_origin does and therefore what `fingerprint` already does — so an
    # operation's key and a finding's fingerprint agree about what an origin is.
    assert (operation_key("http://app.test:80/x", "GET", ["a"])
            == operation_key("http://app.test/x", "GET", ["a"])
            == "GET http://app.test:80/x [a]")
    assert operation_key("https://app.test/x", "GET", ["a"]) == "GET https://app.test:443/x [a]"
    # And a non-default port is a different operation, not the same one.
    assert (operation_key("http://app.test:8081/x", "GET", ["a"])
            != operation_key("http://app.test/x", "GET", ["a"]))


def test_the_identity_is_not_in_the_key():
    """Identity keys the OBSERVATION, not the operation.

    Two identities observing one operation is the entire point of the
    differential; if identity were in the key the arms could never agree, which
    is the defect this file exists for. Keeping their findings and evidence
    separate is the job of the observation rows, which are keyed by identity_id.
    """
    from orchestrator.integrations.contracts import Endpoint

    # Two arms, two identities, the same form — including the hardened arm's
    # extra token, which is what actually happened on DVWA.
    reader = Endpoint(url="http://app.test/vulnerabilities/sqli/?Submit=Submit",
                      method="GET", source="form", identity="reader", parameters=["id"])
    admin = Endpoint(url="http://app.test/vulnerabilities/sqli/?Submit=Submit"
                         "&user_token=b3ae1ff6aafb9151ef0c06930815107d",
                     method="GET", source="form", identity="admin", parameters=["id"])

    assert reader.identity != admin.identity
    assert reader.url != admin.url, "the observations should differ; each keeps what it saw"
    assert (operation_key(reader.url, reader.method, reader.parameters)
            == operation_key(admin.url, admin.method, admin.parameters)), (
        "two identities observing one form produced two operations, so no "
        "differential between them can be one variable")

    # operation_key takes no identity argument at all, so no caller can
    # accidentally make one.
    import inspect
    assert "identity" not in inspect.signature(operation_key).parameters


def test_a_target_cannot_choose_the_operation_key():
    """The forgery check.

    Every input to this key is either lane-authored (the method) or a NAME the
    target put on its own form — never a VALUE. A value is the part a target
    rotates per request, and rotating one is exactly what forked the two arms.
    So a target varying values cannot split one operation into many, which is
    the denial-of-coverage version of this bug.
    """
    rotating = [operation_key(f"http://app.test/p?tok={n:032x}&Submit=Submit", "GET", ["id"])
                for n in range(5)]
    assert len(set(rotating)) == 1, (
        "a target rotating a query value produced %d operations: %r"
        % (len(set(rotating)), sorted(set(rotating))))

    # And the other direction: it must not be able to MERGE two operations by
    # naming an input the same on different paths.
    assert (operation_key("http://app.test/a", "GET", ["id"])
            != operation_key("http://app.test/b", "GET", ["id"]))


# ------------------------------------------- the comparison, against the store

@pytest.fixture
async def store(tmp_path, monkeypatch):
    """A real assessment store, so the comparison is tested through SQL."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


async def observe(db, identity, url, parameters, method="GET", sources=("form",)):
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, method, identity, json.dumps(list(sources)), json.dumps(parameters)))


SQLI = "http://app.test/vulnerabilities/sqli/"


async def test_the_operation_set_now_matches_but_the_differential_is_still_refused(store):
    """The correction that matters, and the reason this gate is not a rubber stamp.

    `reader` saw the form at security=low, `admin` saw it at impossible with a
    single-use token baked into the URL. Two rows, two URL strings, and under
    `operation_key` ONE operation — which is the improvement the key buys: the
    arms now agree about what exists, where before they shared 1 of 8 pairs.

    And the differential is refused anyway. Agreeing about the surface is not the
    same as having tested it: each arm still issued a DIFFERENT request, and on
    the hardened arm that request carried a token that was stale by the time it
    ran. An independent pass measured a live run scoring a perfect shared-surface
    fraction of 1.0 while all eight probe sets received zero bytes — so a gate
    that stopped at set equality would be the vacuous pass this project keeps
    removing.

    What this means for the lab: DVWA's two security levels cannot provide a valid
    authorization differential at all, however well the surfaces are normalised.
    Two principals at ONE level can. That is a conclusion about the lab, not a
    defect in the comparison.
    """
    from orchestrator.integrations.inventory import compare_arms, operations

    await observe(store, "reader", SQLI + "?Submit=Submit", ["id"])
    await observe(store, "admin", SQLI + "?Submit=Submit&user_token=b3ae1ff6aafb9151ef0c06930815107d", ["id"])

    result = await compare_arms("s", "reader", "admin")

    # The surfaces agree — the whole point of the operation key.
    assert result["only_in_first"] == [] and result["only_in_second"] == []
    assert result["summary"] == "1 of 1 operations seen by both"

    # And the differential is refused, naming why, with the value withheld.
    assert not result["comparable"]
    assert result["refused_because"] == ["per_arm_value_in_operation"]
    divergence = result["per_arm_value_in_operation"][0]
    assert divergence["differing_query_fields"] == ["Submit", "user_token"]
    assert "b3ae1ff6" not in json.dumps(result), (
        "a target-controlled companion VALUE reached the comparison output")

    # Nothing was thrown away: the operation keeps BOTH observations, so a reader
    # can still see the token the hardened arm was served.
    grouped = await operations("s")
    assert len(grouped) == 1
    entry = next(iter(grouped.values()))
    assert sorted(entry["identities"]) == ["admin", "reader"]
    assert len(entry["observations"]) == 2
    assert any("user_token=" in o["url"] for o in entry["observations"])


async def test_two_principals_at_one_level_are_comparable(store):
    """The pair that CAN provide a differential: same configuration, two
    identities, so both arms issue the identical request and the only variable is
    who made it.

    Measured on DVWA: admin and gordonb, both at security=low, both produce
    `/vulnerabilities/sqli/?Submit=Submit` byte for byte.
    """
    from orchestrator.integrations.inventory import compare_arms

    await observe(store, "admin", SQLI + "?Submit=Submit", ["id"])
    await observe(store, "gordonb", SQLI + "?Submit=Submit", ["id"])

    result = await compare_arms("s", "admin", "gordonb")
    assert result["comparable"], result["refused_because"]
    assert result["summary"] == "1 of 1 operations seen by both"


async def test_an_identity_compared_with_itself_is_refused(store):
    """Perfect agreement, and it proves nothing."""
    from orchestrator.integrations.inventory import compare_arms

    await observe(store, "admin", SQLI + "?Submit=Submit", ["id"])
    result = await compare_arms("s", "admin", "admin")
    assert not result["comparable"]
    assert "arms_share_one_identity" in result["refused_because"]


async def test_the_comparison_reports_a_genuine_divergence(store):
    """The negative control, and the reason this is not a rubber stamp.

    A comparison that cannot fail proves nothing. Here one arm reaches a page the
    other never does — the real failure an authenticated crawl hits when a
    session expires halfway — and the gate must say so rather than average it
    away.
    """
    from orchestrator.integrations.inventory import compare_arms

    await observe(store, "reader", SQLI + "?Submit=Submit", ["id"])
    await observe(store, "admin", SQLI + "?Submit=Submit", ["id"])
    await observe(store, "admin", "http://app.test/admin/users", ["page"], sources=("katana",))

    result = await compare_arms("s", "reader", "admin")
    assert not result["comparable"]
    assert result["only_in_second"] == ["GET http://app.test:80/admin/users [page]"]
    assert result["only_in_first"] == []
    assert result["summary"] == "1 of 2 operations seen by both"


async def test_a_different_method_makes_the_arms_incomparable(store):
    """Merging methods would have hidden this, which is why E-007 forbids it."""
    from orchestrator.integrations.inventory import compare_arms

    await observe(store, "reader", "http://app.test/items", ["id"], method="GET")
    await observe(store, "admin", "http://app.test/items", ["id"], method="POST")

    result = await compare_arms("s", "reader", "admin")
    assert not result["comparable"]
    assert result["summary"] == "0 of 2 operations seen by both"


async def test_an_arm_that_discovered_nothing_is_not_quietly_comparable(store):
    """The failure this codebase keeps producing: a vacuous pass.

    If `admin` never got a session, its arm is empty. Two empty sets are equal,
    so a naive set comparison calls that a perfect match — a confident green from
    an arm that did nothing. The gate must distinguish "the same surface" from
    "no surface", so a caller is given the shared count and can require it.
    """
    from orchestrator.integrations.inventory import compare_arms

    await observe(store, "reader", SQLI + "?Submit=Submit", ["id"])

    result = await compare_arms("s", "reader", "admin")
    assert not result["comparable"], "an empty arm was reported as comparable"
    assert result["only_in_first"] == ["GET http://app.test:80/vulnerabilities/sqli/ [id]"]

    both_empty = await compare_arms("s", "ghost-one", "ghost-two")
    assert both_empty["shared"] == []
    assert not both_empty["comparable"], (
        "two arms that discovered nothing agreed vacuously and were reported as "
        "comparable — the commonest way this gate gets reported as passed")
    assert "no_shared_operations" in both_empty["refused_because"]
    assert both_empty["summary"] == "0 of 0 operations seen by both"


def test_a_page_never_merges_with_that_path_s_form_action():
    """Why the testable names are IN the key, and it is a safety property.

    An operation key of (origin, method, path) alone — the obvious simplification,
    and one an adversarial review proposed — collapses `/vulnerabilities/csrf/`
    together with `/vulnerabilities/csrf/?Change=Change`. Those are a page and an
    ACTION: requesting the second sets DVWA's admin password to the md5 of an
    empty string. Merging them would put a state-changing request under the same
    identity as the page that merely displays the form, which is how a read-only
    case reaches an action.

    The testable names separate them, because a page has none and the form's
    action has the form's inputs. Measured on the real arms, that same
    simplification merged four operations per arm.
    """
    from orchestrator.integrations.contracts import parameter_names

    page = "http://dvwa.test/vulnerabilities/csrf/"
    action = "http://dvwa.test/vulnerabilities/csrf/?Change=Change"

    assert operation_key(page, "GET", parameter_names(page)) != \
        operation_key(action, "GET", ["password_new", "password_conf"]), \
        "a page and its form's action became one operation"

    # And the simplification, spelled out, so the reason is not lost:
    assert operation_key(page, "GET", []) == operation_key(action, "GET", []), (
        "this assertion documents the REJECTED design — if it ever fails the "
        "comment above needs rewriting, not the code")
