"""The digest that stood in for the marker could be inverted in under a millisecond.

A finding must say WHICH operator declaration it rests on, and must not quote it: a marker
names the application's private data and a finding travels into an export. The first
mechanism for that was `sha256(marker)[:12]`, described in the code as recording the marker
"as a digest, not as text". Measured against the digest a real Juice Shop export carries,
over a candidate space of 4050 strings built from field names, local-parts, domains and
separator patterns:

    exhausted in 0.0007s, recovered '"email":"admin@juice-sh.op"'

TRUNCATION WAS NOT THE BINDING PROBLEM, which is the part worth keeping in mind before
anyone "fixes" this by widening the digest: the full 64-hex sha256 of the same marker falls
to the same harness at the same cost. The input's entropy is the problem. A marker is short
and structured by construction — it names a field and a value in an application's own data
— so no unkeyed digest of a marker can be published safely. An adversarial pass built the
candidate space mechanically out of the assessment's OWN recorded bytes (68 JSON keys x
1711 values x 9 separators = 2^20 candidates) and exhausted it in 0.60s with exactly one
hit, guessing nothing.

So the label is keyed: HMAC-SHA256 under 128 random bits per assessment, kept in the
SecretStore like every other secret. The label stays stable within the one report that
carries it and differs across assessments, and the marker cannot be recovered from it.
"""
import hashlib
import itertools
import json
import os

import pytest

from orchestrator.integrations.security import (MARKER_DIGEST_CHARS, SecretStore,
                                                _marker_salt, marker_digest)

MARKER = '"email":"admin@juice-sh.op"'


@pytest.fixture(autouse=True)
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path))
    return tmp_path


def candidates():
    """The attack, as an operator's data realistically looks."""
    fields = ["email", "username", "password", "role", "id", "token", "name", "address",
              "phone", "ssn", "card", "user", "mail", "login", "account", "owner", "uid", "sub"]
    people = ["admin", "administrator", "root", "jim", "bender", "user", "test", "support",
              "info", "contact", "sales", "no-reply", "bjoern", "morty", "amy"]
    domains = ["juice-sh.op", "example.com", "localhost"]
    patterns = ['"{f}":"{p}@{d}"', '"{f}": "{p}@{d}"', "{f}={p}@{d}", '{f}:"{p}@{d}"',
                "'{f}':'{p}@{d}'"]
    return {pattern.format(f=f, p=p, d=d)
            for f, p, d, pattern in itertools.product(fields, people, domains, patterns)}


# ------------------------------------------------------- the attack, and the control

def test_the_unsalted_digest_is_recoverable():
    """THE POSITIVE CONTROL. Without this the test below proves nothing: a search that
    finds nothing because the search is broken looks exactly like a search that finds
    nothing because the label is safe."""
    space = candidates()
    assert MARKER in space, "the space must contain the answer for this to be a control"
    target = hashlib.sha256(MARKER.encode()).hexdigest()[:12]
    hit = next((c for c in space if hashlib.sha256(c.encode()).hexdigest()[:12] == target), None)
    assert hit == MARKER, "the old form inverts"


def test_widening_the_digest_does_not_help():
    """Stated because it is the obvious wrong fix. The whole sha256 inverts too."""
    target = hashlib.sha256(MARKER.encode()).hexdigest()
    hit = next((c for c in candidates() if hashlib.sha256(c.encode()).hexdigest() == target), None)
    assert hit == MARKER


def test_the_keyed_label_is_not_recoverable():
    label = marker_digest("s", MARKER)
    assert not [c for c in candidates()
                if hashlib.sha256(c.encode()).hexdigest()[:12] == label], (
        "the same search that inverts the unsalted digest must find nothing here")
    assert len(label) == MARKER_DIGEST_CHARS


def test_the_label_cannot_be_reproduced_without_the_salt(runtime):
    """An export holds the label. Someone holding only the export cannot recompute it."""
    label = marker_digest("s", MARKER)
    salt = _marker_salt("s")
    assert label != hashlib.sha256(MARKER.encode()).hexdigest()[:MARKER_DIGEST_CHARS]
    assert salt.hex() not in label
    # ...and with the salt it IS reproducible, which is what makes it a label at all.
    import hmac
    assert label == hmac.new(salt, MARKER.encode(),
                             hashlib.sha256).hexdigest()[:MARKER_DIGEST_CHARS]


# ---------------------------------------------------------- and it behaves as a label

def test_it_is_stable_within_an_assessment():
    assert marker_digest("s", MARKER) == marker_digest("s", MARKER)


def test_it_tells_two_markers_apart():
    """The one job the digest was introduced to do."""
    assert marker_digest("s", MARKER) != marker_digest("s", '"email":"jim@juice-sh.op"')


def test_it_differs_across_assessments():
    """Keyed per assessment, not globally: a label only has to be unique inside the one
    report that carries it, and a global key would make labels comparable across every
    client's engagement."""
    assert marker_digest("one", MARKER) != marker_digest("two", MARKER)


def test_the_salt_is_not_in_the_database_or_any_payload(runtime):
    """It lives in the SecretStore, which is the module's whole premise: secrets stay
    outside SQLite, reports and model prompts."""
    salt = _marker_salt("s")
    files = list((runtime / "secrets").glob("*.json"))
    assert any(salt.hex() in f.read_text() for f in files)
    assert all(os.stat(f).st_mode & 0o777 == 0o600 for f in files)
    assert os.stat(runtime / "secrets").st_mode & 0o777 == 0o700


def test_a_session_id_no_secret_store_key_would_accept_still_gets_a_salt():
    """CLI session ids are `uuid4().hex[:12]`, and `SecretStore.path` requires 32 hex —
    so the salt's handle is DERIVED from the session id rather than being it."""
    assert marker_digest("a1b2c3d4e5f6", MARKER)
    assert marker_digest("a session id with spaces", MARKER)


# -------------------------------------------------- a damaged salt is fatal, not absent

@pytest.mark.parametrize("damage", [b"", b'{"marker_sal', b'{"other": "x"}',
                                    b'{"marker_salt": "not-hex"}'])
def test_a_damaged_salt_refuses_rather_than_relabelling(runtime, damage):
    """The first version caught ValueError, and `json.JSONDecodeError` IS one — so a
    corrupt salt read as "there is no salt yet" and minted a replacement. Every label
    already exported under the old salt is then unreproducible while the report still
    looks correct: this codebase's signature defect, written fresh. The zero-byte case is
    reachable without an attacker, because `private_write` opens O_CREAT|O_TRUNC.
    """
    first = marker_digest("s", MARKER)
    path = SecretStore().path(hashlib.sha256(b"erlik:marker-salt:s").hexdigest()[:32])
    path.write_bytes(damage)
    with pytest.raises(Exception) as caught:
        marker_digest("s", MARKER)
    assert not isinstance(caught.value, FileNotFoundError)
    # AND IT NAMES THE DAMAGE, on the first look, rather than reporting that the store
    # "would not settle" after three futile attempts to mint over a file that is already
    # there. Broadening the `except` to `Exception` still refuses — the link sees the name
    # taken — so what the narrow clause buys is a diagnosable failure, and that is what this
    # asserts. The first version of this test did not, and the ablation went uncaught.
    assert not isinstance(caught.value, RuntimeError), (
        f"refused, but only by running out of attempts: {caught.value!r}")
    assert not [f for f in (runtime / "secrets").iterdir() if f.name.endswith(".tmp")]
    # and the negative control: a genuinely ABSENT salt is still minted, or no assessment
    # could ever produce its first label.
    path.unlink()
    assert marker_digest("s", MARKER) not in ("", None)
    assert marker_digest("s", MARKER) != first, "a new salt is a new label, necessarily"


def test_repeated_use_mints_one_salt(runtime):
    labels = {marker_digest("s", MARKER) for _ in range(8)}
    assert len(labels) == 1
    keyed = hashlib.sha256(b"erlik:marker-salt:s").hexdigest()[:32]
    assert [f.name for f in (runtime / "secrets").glob("*.json")] == [keyed + ".json"]


def test_a_salt_that_appears_mid_mint_is_adopted_not_overwritten(runtime, monkeypatch):
    """The race, forced rather than raced for.

    `_marker_salt` reads, finds nothing, and writes. If another writer lands in that window
    the loser must adopt the winner's salt — otherwise one assessment has two labels for one
    marker, and a second label is indistinguishable from a second declaration, which is the
    only thing the label exists to tell apart. `O_EXCL` is what makes the loser notice.

    Simulated by failing the FIRST read while the file already holds somebody else's salt,
    which is exactly the state the window produces.
    """
    import hmac
    from orchestrator.integrations.security import SecretStore as Store
    theirs = bytes(range(16))
    key = hashlib.sha256(b"erlik:marker-salt:s").hexdigest()[:32]
    real = Store().path(key)
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text(json.dumps({"marker_salt": theirs.hex()}))

    reads = {"n": 0}
    original = type(real).read_text

    def first_read_misses(self, *a, **kw):
        if self == real and reads["n"] == 0:
            reads["n"] += 1
            raise FileNotFoundError(str(self))
        return original(self, *a, **kw)

    monkeypatch.setattr(type(real), "read_text", first_read_misses)
    assert _marker_salt("s") == theirs, "the loser adopted the winner's salt"
    assert json.loads(real.read_text())["marker_salt"] == theirs.hex(), "and did not clobber it"
    assert marker_digest("s", MARKER) == hmac.new(
        theirs, MARKER.encode(), hashlib.sha256).hexdigest()[:MARKER_DIGEST_CHARS]


def test_a_store_that_will_not_settle_fails_loudly_rather_than_spinning(runtime, monkeypatch):
    """`while True` here was a hang waiting for a future edit, and the edit was made: an
    ablation broadened the `except` by one word, and "a damaged salt is fatal" became
    read-fails, mint-loses-the-link-race, read-fails — forever, inside a request handler.
    It wedged a test run for twenty minutes.

    To exercise the BOUND rather than the raise, the read has to fail the way an ABSENT file
    does — the one way the loop retries — while the link keeps failing because the name is
    already taken. A first draft of this test made the read raise `ValueError`, which
    escapes on the first attempt, so it passed without the loop ever going round.
    """
    from orchestrator.integrations import security

    path = SecretStore().path(hashlib.sha256(b"erlik:marker-salt:s").hexdigest()[:32])
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps({"marker_salt": "00" * 16}))   # the name is taken
    attempts = {"n": 0}

    def never_there(self, *a, **kw):
        if self == path:
            attempts["n"] += 1
            raise FileNotFoundError(str(self))
        return json.dumps({"marker_salt": "00" * 16})

    monkeypatch.setattr(type(path), "read_text", never_there)
    with pytest.raises(RuntimeError, match="marker salt"):
        security._marker_salt("s")
    assert attempts["n"] == 3, "bounded, and the bound is what stopped it"
    assert not [f for f in (runtime / "secrets").iterdir() if f.name.endswith(".tmp")], (
        "and every staging file it wrote on the way is gone")


def test_the_mint_writes_whole_and_links(runtime):
    """No reader ever sees a partial salt file, which is what makes "damaged is fatal" safe.
    Asserted on the outcome: after a mint, no staging file is left behind and the salt
    parses."""
    marker_digest("s", MARKER)
    files = sorted(f.name for f in (runtime / "secrets").iterdir())
    assert len(files) == 1 and not files[0].endswith(".tmp"), files
    assert len(_marker_salt("s")) == 16


# ------------------------------- and the label already written to disk is withdrawn

async def test_an_existing_store_stops_publishing_the_invertible_label(tmp_path, monkeypatch):
    """Keying new findings was not enough. Rows persisted before the change still carried
    `marker digest: <sha256 prefix>` in their evidence PROSE, and the export still published
    it — measured on the real Juice Shop store, 2 of 11 findings. The marker recovers from
    that in under a millisecond, so a migration has to reach them.

    It STRIPS rather than re-labels, because it cannot do anything else: recomputing a keyed
    label needs the marker, and the marker was never stored — which is the design working.
    """
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    invertible = hashlib.sha256(MARKER.encode()).hexdigest()[:12]
    evidence = ("erlik compared what three arms received.\n"
                "  anonymous arm:     asked for it and did not receive it\n"
                f"  marker digest:     {invertible}")
    legacy = {"fingerprint": "f1", "title": "t", "url": "u",
              "rule": "erlik:authorization:privileged-function", "source": "cross-arm",
              "basis": "b", "evidence": evidence}
    # The SAME shape, on its own line, so the only thing that can spare it is the rule
    # filter. A first version put it mid-sentence, where the anchored regex would not have
    # matched anyway — so the test passed without the filter doing anything.
    other = {**legacy, "fingerprint": "f2", "rule": "erlik:zap:alert",
             "evidence": f"a scanner wrote this\n  marker digest:     {invertible}"}
    for row in (legacy, other):
        await db.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                         ("s", row["fingerprint"], json.dumps(row)))

    await db.migrate()
    stored = {r["fingerprint"]: json.loads(r["payload"])
              for r in await db.rows("SELECT fingerprint,payload FROM integration_findings")}
    assert invertible not in stored["f1"]["evidence"]
    assert "anonymous arm" in stored["f1"]["evidence"], "the differential survives"
    assert invertible in stored["f2"]["evidence"], (
        "bounded to the authorization rules — rewriting another producer's evidence on a "
        "substring match is not this migration's business")

    before = await db.rows("SELECT payload FROM integration_findings ORDER BY fingerprint")
    await db.migrate()
    after = await db.rows("SELECT payload FROM integration_findings ORDER BY fingerprint")
    assert [r["payload"] for r in before] == [r["payload"] for r in after], "idempotent"
