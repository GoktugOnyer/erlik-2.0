"""Nothing in `inventory` ever read `integration_stages.status`.

It selected `id` and `result`, so `coverage`, `arm_responses` and both cross-arm checks were
blind to whether an arm finished reading. Measured on a copy of the real Juice Shop run, with
the customer arm's stages marked `partial` and its two decisive captures deleted:

    complete run   findings=2 checked=225 refused=[] not_shared=5 not_comparable=15
    half run       findings=0 checked=225 refused=[] not_shared=5 not_comparable=15

Every count byte-identical, two true positives gone, and nothing said so. An operator reading
that sees 225 operations checked, nothing refused, and no findings.

THE MECHANISM WAS ONE `.get`. Clause 2 asked `carries(unprivileged_saw.get(key, ""))`, so an
absent capture read as "this arm did not receive the data" — which is what a denial looks
like. Clause 3, three lines below, already drew exactly this distinction for the ANONYMOUS arm
and says so in as many words: "`get` with a default would read 'the anonymous arm never probed
this' as 'the anonymous arm was refused', which is the unrun-clause defect this project keeps
removing." The arm the finding is ABOUT did not get the same care, and neither did the
object-level check's owner arm.

IT IS REPORTED, NOT REFUSED, which reverses this module's usual answer on purpose. A refusal
makes `authorization_findings` persist nothing — and an incomplete arm can only LOSE findings,
never invent one, because a finding still needs positive evidence from both arms plus an
anonymous arm that asked and was refused. Refusing would discard the true positives a half run
did find in order to report the ones it missed.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import FINISHED_STAGE_STATUSES

MARKER = '"email":"target@app.test"'
MARKED = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
          '{"data":{"id":7,"email":"target@app.test"}}')
REFUSED = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\nno"
URL = "http://app.test/api/Users"


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    handles = {
        "admin": SecretStore().put({"name": "admin", "target_origin": "http://app.test",
                                    "role": "admin", "subject_id": "1"}),
        "jim": SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                                  "role": "customer", "subject_id": "2"}),
    }
    return {"db": db, "h": handles}


async def surface(lab, arm, output, url=URL, status="completed"):
    """One recorded read of `url` by `arm`, with the stage row that owns it."""
    stage = uuid.uuid4().hex
    await lab["db"].execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status) "
        "VALUES(?,?,?,?,?)", (stage, "s", "testcases", arm, status))
    await lab["db"].execute(
        "INSERT OR IGNORE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
        ("s", url, "GET", arm, json.dumps(["katana"])))
    if output is None:
        return None
    return await lab["db"].evidence("s", stage, "testcase:ERLIK-SURFACE-READ", json.dumps({
        "test_case_id": "ERLIK-SURFACE-READ", "target": {"url": url},
        "steps": [{"step": "read", "output": output}]}))


async def check(lab, **kw):
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    return await cross_arm_privileged_function("s", lab["h"]["admin"], lab["h"]["jim"],
                                               MARKER, anonymous="anonymous", **kw)


# ---------------------------------------------------- never asked is not did not receive

async def test_a_complete_run_is_silent_about_all_of_this(lab):
    """THE CONTROL, first. Every number below must be empty on a healthy run, or the report
    becomes noise and an operator learns to skip it."""
    for arm, out in (("admin", MARKED), ("jim", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out)
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [URL], "the finding must survive"
    assert result["operations_the_other_arm_did_not_probe"] == []
    assert result["arms_with_unfinished_stages"] == {}
    assert "NOT A CLEAN RESULT" not in result["establishes"]


async def test_an_operation_the_other_arm_never_probed_is_named(lab):
    """The absent capture used to read as a denial, so the operation vanished in silence."""
    await surface(lab, lab["h"]["admin"], MARKED)
    await surface(lab, lab["h"]["jim"], None)          # an endpoint row, and no capture
    # ...but the arm DID read elsewhere, or the empty-arm guard below would refuse instead and
    # this would be testing a different clause.
    await surface(lab, lab["h"]["jim"], MARKED, url="http://app.test/other")
    await surface(lab, "anonymous", REFUSED)
    result = await check(lab)
    assert result["findings"] == [], "no capture is not evidence of a crossing"
    assert result["operations_the_other_arm_did_not_probe"] == [URL]
    assert "NOT A CLEAN RESULT" in result["establishes"]


async def test_a_genuine_denial_is_still_not_a_finding_and_not_a_blind_spot(lab):
    """The distinction, in the direction that matters: an arm that ASKED and was refused is a
    clean negative, and must not be reported as an operation nobody probed."""
    for arm, out in (("admin", MARKED), ("jim", REFUSED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out)
    result = await check(lab)
    assert result["findings"] == []
    assert result["operations_the_other_arm_did_not_probe"] == []
    assert "NOT A CLEAN RESULT" not in result["establishes"]


async def test_the_object_level_check_draws_the_same_distinction(lab):
    """It had the identical `.get(key, "")` on the owner's arm."""
    from orchestrator.integrations.inventory import cross_arm_authorization
    owned = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
             '{"data":{"UserId":1}}')
    url = "http://app.test/rest/basket/1"
    await surface(lab, lab["h"]["jim"], owned, url=url)
    await surface(lab, lab["h"]["admin"], None, url=url)
    await surface(lab, lab["h"]["admin"], owned, url="http://app.test/rest/basket/9")
    await surface(lab, "anonymous", REFUSED, url=url)
    result = await cross_arm_authorization("s", lab["h"]["jim"], lab["h"]["admin"],
                                          "data.UserId", "anonymous")
    assert result["operations_the_other_arm_did_not_probe"] == [url]


# ----------------------------------------------------------- and the arm that did not finish

@pytest.mark.parametrize("status", ["partial", "failed", "cancelled", "running", "queued",
                                    "needs_auth"])
async def test_an_arm_with_an_unfinished_stage_is_named(lab, status):
    for arm, out in (("admin", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out)
    await surface(lab, lab["h"]["jim"], MARKED, status=status)
    result = await check(lab)
    assert lab["h"]["jim"] in result["arms_with_unfinished_stages"]
    assert result["arms_with_unfinished_stages"][lab["h"]["jim"]][0][1] == status
    assert "NOT A CLEAN RESULT" in result["establishes"]


@pytest.mark.parametrize("status", FINISHED_STAGE_STATUSES)
async def test_a_finished_stage_is_not_reported(lab, status):
    """`skipped` belongs with `completed`: an adapter the operator did not select read nothing
    and lost nothing. The rule is `service.run`'s own rollup, from one shared list."""
    for arm, out in (("admin", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out)
    await surface(lab, lab["h"]["jim"], MARKED, status=status)
    result = await check(lab)
    assert result["arms_with_unfinished_stages"] == {}


async def test_the_findings_a_half_run_did_see_are_kept(lab):
    """The reason this reports rather than refuses. An incomplete arm loses findings without
    inventing any — a finding still needs positive evidence from both arms and an anonymous
    arm that asked and was refused — so refusing would discard the true positives in order to
    report the missed ones."""
    from orchestrator.integrations.inventory import authorization_findings
    other = "http://app.test/api/Users/7"
    for arm, out in (("admin", MARKED), ("jim", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out, url=other, status="partial")
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [other]
    assert result["refused_because"] == [], "reported, not refused"
    assert authorization_findings("http://app.test/", "function", result), (
        "a refusal would have persisted nothing, losing a true positive to report a gap")


async def test_the_anonymous_arm_counts_too(lab):
    """It is compared like any other, so its stages gate nothing but are reported."""
    for arm, out in (("admin", MARKED), ("jim", MARKED)):
        await surface(lab, lab["h"][arm], out)
    await surface(lab, "anonymous", REFUSED, status="failed")
    result = await check(lab)
    assert "anonymous" in result["arms_with_unfinished_stages"]


# ------------------------------------- and an arm with NOTHING is a different answer again

async def test_an_arm_with_no_evidence_at_all_refuses(lab):
    """`anonymous_arm_did_not_run` guarded the third arm all along; the two being compared had
    no equivalent. With one arm's stage `skipped` — which `FINISHED_STAGE_STATUSES` calls
    finished, and rightly — and its artifacts absent, the object-level check reported
    `checked=0 findings=0 refused=[]` with no caveat and no unfinished arm: a clean-looking
    zero over nothing.

    THIS refuses where the half run reports, and the difference is the point. An arm that read
    PART of the surface still produces findings as interpretable as a complete run's, so
    refusing there discards evidenced HIGHs. An arm with NOTHING has no findings to discard
    and no comparison to interpret.
    """
    await surface(lab, lab["h"]["admin"], MARKED)
    await surface(lab, "anonymous", REFUSED)
    # jim's stage exists and is `skipped`; it recorded nothing.
    await surface(lab, lab["h"]["jim"], None, status="skipped")
    result = await check(lab)
    assert "unprivileged_arm_did_not_run" in result["refused_because"]
    assert result["findings"] == []


async def test_the_object_check_guards_both_of_its_arms(lab):
    from orchestrator.integrations.inventory import cross_arm_authorization
    owned = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
             '{"data":{"UserId":1}}')
    await surface(lab, lab["h"]["admin"], owned)
    await surface(lab, "anonymous", REFUSED)
    await surface(lab, lab["h"]["jim"], None, status="skipped")
    result = await cross_arm_authorization("s", lab["h"]["jim"], lab["h"]["admin"],
                                          "data.UserId", "anonymous")
    assert "caller_arm_did_not_run" in result["refused_because"]


async def test_a_refusal_here_persists_nothing(lab):
    """Which is why it must only fire when there is nothing to lose."""
    from orchestrator.integrations.inventory import authorization_findings
    await surface(lab, lab["h"]["admin"], MARKED)
    await surface(lab, "anonymous", REFUSED)
    await surface(lab, lab["h"]["jim"], None, status="skipped")
    assert authorization_findings("http://app.test/", "function", await check(lab)) == []


async def test_an_arm_that_read_something_is_not_refused(lab):
    """The negative control that separates the two answers: one capture is enough to make the
    comparison interpretable, and then the half-run reporting takes over."""
    for arm, out in (("admin", MARKED), ("jim", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out, status="partial")
    result = await check(lab)
    assert result["refused_because"] == []
    assert [f["url"] for f in result["findings"]] == [URL]


async def test_the_privileged_arm_with_nothing_refuses_too(lab):
    """Both arms, not just the one the finding is about. The privileged arm is where clause 1
    gets its "there is a privileged function here at all" — with no evidence it cannot, and
    every operation silently fails clause 1 rather than the check saying why."""
    await surface(lab, lab["h"]["jim"], MARKED)
    await surface(lab, "anonymous", REFUSED)
    await surface(lab, lab["h"]["admin"], None, status="skipped")
    result = await check(lab)
    assert "privileged_arm_did_not_run" in result["refused_because"]


async def test_the_object_checks_owner_arm_with_nothing_refuses_too(lab):
    """The owner arm is the corroborating one: with no evidence nothing can corroborate, and
    the check used to report that as "no crossing found"."""
    from orchestrator.integrations.inventory import cross_arm_authorization
    owned = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
             '{"data":{"UserId":1}}')
    await surface(lab, lab["h"]["jim"], owned)
    await surface(lab, "anonymous", REFUSED)
    await surface(lab, lab["h"]["admin"], None, status="skipped")
    result = await cross_arm_authorization("s", lab["h"]["jim"], lab["h"]["admin"],
                                          "data.UserId", "anonymous")
    assert "owner_arm_did_not_run" in result["refused_because"]


# --------------------------------------------- and it is scoped to what the comparison reads

async def test_a_crawler_that_hit_its_budget_is_not_an_unfinished_arm(lab):
    """THE NOISE THIS NEARLY SHIPPED AS A SIGNAL.

    A real three-arm Juice Shop run has all three arms' katana stages `partial` with "request
    or URL budget exhausted" — the crawler doing exactly what `max_urls` told it — while every
    testcases stage is `completed`. Unscoped, this named all three arms and `establishes`
    called a correct result unclean. Across the eleven lane databases on this machine, 7 of 57
    stage rows are `partial` and all seven are that same budget message.

    `arm_responses` reads only evidence whose kind starts with `testcase:`, which the catalogue
    adapter writes, so a truncated crawl is not a fact about the comparison's inputs. It is
    reported where it belongs, as the arm-wide truncation `coverage()` indexes.
    """
    for arm, out in (("admin", MARKED), ("jim", MARKED), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), out)
    for arm in ("admin", "jim"):
        await lab["db"].execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,reason) "
            "VALUES(?,?,?,?,?,?)", (uuid.uuid4().hex, "s", "katana", lab["h"][arm], "partial",
                                    "request or URL budget exhausted"))
    result = await check(lab)
    assert result["arms_with_unfinished_stages"] == {}, (
        "a crawler obeying max_urls is not an arm that failed to read")
    assert "NOT A CLEAN RESULT" not in result["establishes"]
    assert [f["url"] for f in result["findings"]] == [URL], "and the finding still stands"


async def test_the_scope_is_the_adapter_whose_evidence_is_read(lab):
    """Stated as a relation, not a literal: whatever `arm_responses` consumes is what
    `unfinished_stages` must look at, so the two cannot drift."""
    import inspect

    from orchestrator.integrations.inventory import COMPARED_STAGE_ADAPTERS, arm_responses
    assert COMPARED_STAGE_ADAPTERS == ("testcases",)
    assert 'startswith("testcase:")' in inspect.getsource(arm_responses), (
        "arm_responses no longer filters on the testcase kind; COMPARED_STAGE_ADAPTERS "
        "needs to follow it")
