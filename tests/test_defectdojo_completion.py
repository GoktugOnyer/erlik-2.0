"""Network-free synchronization tests against a stateful API double."""
import copy
import json
import pytest
from pydantic import ValidationError
from orchestrator.integrations import defectdojo, service, persistence as db
from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.security import SecretStore, runtime_root


@pytest.fixture
async def dojo(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setenv('ERLIK_INTEGRATION_DATA', str(tmp_path / 'runtime'))
    monkeypatch.setattr(original, 'DB_DIR', tmp_path)
    monkeypatch.setattr(original, 'DB_PATH', tmp_path / 'test.db')
    await original.init_db()
    await db.migrate()
    await service.register('s', 'https://app.test', AssessmentConfig(scope={'allow_hosts': ['app.test'], 'allow_ports': [443]}))
    class FakeSandbox:
        def __init__(self, *a, **kw):
            assert kw['services'] == ['https://dojo.test']
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
    monkeypatch.setattr(defectdojo, 'Sandbox', FakeSandbox)
    class Remote:
        calls = []
        findings = {}
        reject_patch = False
        async def rpc(self, sandbox, request):
            self.calls.append(copy.deepcopy(request))
            method = request.get('method', 'POST')
            if method == 'GET':
                body = {'results': list(self.findings.values()), 'next': None}
            elif method == 'PATCH':
                if self.reject_patch:
                    return {'status': 500, 'body': 'upstream failed'}
                key = int(request['url'].rstrip('/').rsplit('/', 1)[1])
                self.findings[key].update(request['body'])
                body = self.findings[key]
            else:
                assert request['fields']['close_old_findings'] == 'false'
                assert request['fields']['close_old_findings_product_scope'] == 'false'
                assert request['fields']['auto_create_context'] == 'false'
                for finding in request['report']['findings']:
                    key = len(self.findings) + 1
                    self.findings[key] = dict(finding, id=key, test=42)
                body = {'test': 42}
            return {'status': 200, 'body': json.dumps(body)}
    remote = Remote()
    monkeypatch.setattr(defectdojo, 'rpc', remote.rpc)
    remote.secret = SecretStore().put({'token': 'only-in-runtime'})
    remote.config = defectdojo.ExportConfig(server='https://dojo.test', secret_id=remote.secret, test_id=42)
    yield remote


async def put_finding(fingerprint='fingerprint-one', **overrides):
    data = dict(fingerprint=fingerprint, title='Original finding', basis='Deterministic evidence',
                severity='medium', confidence='confirmed', url='https://app.test/private', triage_state='open')
    data.update(overrides)
    await db.execute('INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)', ('s', fingerprint, json.dumps(data)))


@pytest.mark.parametrize('fields', [dict(action='import', test_id=4), dict(action='import', engagement_id=3),
    dict(action='import', engagement_id=3, test_title=' '), dict(test_id=2, engagement_id=3), dict(),
    dict(action='import', test_id=2, engagement_id=3, test_title='test')])
def test_explicit_import_destination_validation(fields):
    with pytest.raises(ValidationError):
        defectdojo.ExportConfig(server='https://dojo.test', secret_id='id', **fields)


async def test_initial_import_maps_test_and_unchanged_is_noop(dojo):
    await put_finding()
    cfg = defectdojo.ExportConfig(server='https://dojo.test/', secret_id=dojo.secret, action='import', engagement_id=17, test_title='Client web app')
    first = await defectdojo.export('s', cfg)
    count = len(dojo.calls)
    repeat = await defectdojo.export('s', cfg)
    assert first['id'] == repeat['id']
    assert first['remote_test_id'] == 42 and first['status'] == 'completed'
    assert len(dojo.calls) == count
    assert dojo.calls[0]['url'].endswith('/import-scan/')
    assert dojo.calls[0]['fields']['engagement'] == '17'
    assert (await db.rows('SELECT * FROM integration_export_destinations'))[0]['remote_test_id'] == 42
    mapping = (await db.rows('SELECT * FROM integration_remote_findings'))[0]
    assert mapping['fingerprint'] == 'fingerprint-one' and mapping['remote_finding_id'] == 1
    content = (runtime_root() / 'evidence' / first['evidence_id']).read_text()
    assert 'only-in-runtime' not in content


async def test_changed_existing_finding_is_patched_not_reimported(dojo):
    await put_finding()
    await defectdojo.export('s', dojo.config)
    await put_finding(title='Updated title', basis='Additional evidence', severity='high')
    result = await defectdojo.export('s', dojo.config)
    assert result['status'] == 'completed'
    assert len(dojo.findings) == 1
    assert dojo.findings[1]['title'] == 'Updated title'
    assert dojo.findings[1]['description'] == 'Additional evidence'
    assert len([r for r in dojo.calls if r.get('method') == 'PATCH']) == 1
    assert len([r for r in dojo.calls if 'report' in r]) == 1
    assert 'endpoints' not in dojo.calls[-1]['body']
    # Reverting to a historical payload still updates the current remote state.
    await put_finding()
    await defectdojo.export('s', dojo.config)
    assert dojo.findings[1]['title'] == 'Original finding'


async def test_import_destination_reuses_created_test_for_next_revision(dojo):
    await put_finding()
    cfg = defectdojo.ExportConfig(server='https://dojo.test', secret_id=dojo.secret, action='import', engagement_id=17, test_title='Client app')
    await defectdojo.export('s', cfg)
    await put_finding('fingerprint-two', title='Second finding')
    second = await defectdojo.export('s', cfg)
    assert second['action'] == 'reimport'
    posts = [r for r in dojo.calls if 'report' in r]
    assert posts[1]['url'].endswith('/reimport-scan/')
    assert posts[1]['fields']['test'] == '42'
    assert len(posts[1]['report']['findings']) == 1
    assert len(dojo.findings) == 2


async def test_partial_assessment_never_closes_absent_remote_finding(dojo):
    await put_finding()
    await put_finding('fingerprint-two', title='Other finding')
    await defectdojo.export('s', dojo.config)
    await db.execute("DELETE FROM integration_findings WHERE fingerprint='fingerprint-two'")
    await db.execute("UPDATE integration_assessments SET status='partial'")
    result = await defectdojo.export('s', dojo.config)
    assert result['status'] == 'completed'
    assert len(dojo.findings) == 2 and all(f['active'] for f in dojo.findings.values())


async def test_local_false_positive_and_reopen_propagate(dojo):
    await put_finding()
    await defectdojo.export('s', dojo.config)
    await put_finding(triage_state='false_positive', triage_note='Reviewed response')
    result = await defectdojo.export('s', dojo.config)
    assert result['status'] == 'completed'
    assert dojo.findings[1]['false_p'] and not dojo.findings[1]['verified'] and not dojo.findings[1]['active']
    await put_finding(triage_state='open')
    await defectdojo.export('s', dojo.config)
    assert dojo.findings[1]['active'] and not dojo.findings[1]['false_p']


async def test_ambiguous_update_blocks_changed_payload_and_other_action(dojo):
    await put_finding()
    await defectdojo.export('s', dojo.config)
    dojo.reject_patch = True
    await put_finding(title='Updated title')
    uncertain = await defectdojo.export('s', dojo.config)
    assert uncertain['status'] == 'uncertain'
    count = len(dojo.calls)
    await put_finding(title='Another title')
    repeat = await defectdojo.export('s', dojo.config)
    assert repeat['id'] == uncertain['id'] and len(dojo.calls) == count


async def test_duplicate_remote_fingerprint_fails_before_any_write(dojo):
    await put_finding()
    dojo.findings = {1: {'id': 1, 'test': 42, 'unique_id_from_tool': 'fingerprint-one'},
                     2: {'id': 2, 'test': 42, 'unique_id_from_tool': 'fingerprint-one'}}
    result = await defectdojo.export('s', dojo.config)
    assert result['status'] == 'failed'
    assert 'Multiple remote' in result['detail']
    assert len(dojo.calls) == 1


async def test_remote_pagination_never_follows_foreign_next_url(dojo, monkeypatch):
    calls = []
    async def fake(sandbox, args):
        calls.append(args['url'])
        page = {'results': [{'id': 1, 'test': 42, 'unique_id_from_tool': 'first'}], 'next': 'https://unselected.test/api/'} if len(calls) == 1 else {'results': [], 'next': None}
        return {'status': 200, 'body': json.dumps(page)}
    monkeypatch.setattr(defectdojo, 'rpc', fake)
    inventory = await defectdojo.remote_inventory(None, dojo.config, 'token', [], 42)
    assert 'first' in inventory
    assert calls[1] == 'https://dojo.test/api/v2/findings/?test=42&limit=100&offset=1'


async def test_read_only_reconciliation_resolves_applied_but_lost_response(dojo, monkeypatch):
    await put_finding()
    await defectdojo.export('s', dojo.config)
    original = dojo.rpc
    async def lost_response(sandbox, args):
        response = await original(sandbox, args)
        if args.get('method') == 'PATCH':
            raise RuntimeError('connection closed after write')
        return response
    monkeypatch.setattr(defectdojo, 'rpc', lost_response)
    await put_finding(title='Applied before disconnect')
    with pytest.raises(RuntimeError):
        await defectdojo.export('s', dojo.config)
    record = (await db.rows("SELECT * FROM integration_exports WHERE status='uncertain'"))[0]
    count = len(dojo.calls)
    monkeypatch.setattr(defectdojo, 'rpc', dojo.rpc)
    resolved = await defectdojo.reconcile(record['id'], dojo.config)
    assert resolved['status'] == 'completed'
    assert all(c.get('method') == 'GET' for c in dojo.calls[count:])
    assert (await defectdojo.export('s', dojo.config))['id'] == record['id']


async def test_reconciliation_keeps_uncertainty_when_remote_fields_differ(dojo):
    await put_finding()
    await defectdojo.export('s', dojo.config)
    dojo.reject_patch = True
    await put_finding(title='Not applied')
    record = await defectdojo.export('s', dojo.config)
    result = await defectdojo.reconcile(record['id'], dojo.config)
    assert result['status'] == 'uncertain'
    assert 'no requests replayed' in result['detail']


def _why(row):
    """Assertion context that is actually diagnostic.

    A bare `assert row['status'] == 'uncertain'` prints the whole sqlite Row,
    and `detail` — the only field that says WHY — is what gets elided.
    """
    return f"status={row['status']!r} detail={row['detail']!r}"


async def test_a_queued_202_import_stays_uncertain_and_blocks(dojo, monkeypatch):
    """The one branch written specifically for 202, which nothing tested.

    `remote()` treats anything but 200/201 as an error, and the `failed`
    override in `export()` carries an explicit `exc.status != 202` so that a
    queued import is NOT downgraded to a clean failure. The distinction is the
    whole point: a 4xx means nothing was written and the export can simply be
    retried, while a 202 means DefectDojo accepted the import for background
    processing and no one yet knows whether it landed. Calling that `failed`
    would invite a retry that silently double-imports.

    docs/integrations.md now promises this to operators, so it is tested.
    """
    await put_finding()

    # 202 on the WRITE only. Returning it for everything made the first call —
    # the inventory GET — fail instead, and a failed READ is correctly `failed`:
    # nothing was written, so there is nothing to be uncertain about. The
    # distinction under test only exists once a write has been issued.
    async def queued(sandbox, request):
        if request.get('method', 'POST') != 'POST':
            return await dojo.rpc(sandbox, request)
        dojo.calls.append(copy.deepcopy(request))
        return {'status': 202, 'body': json.dumps({'message': 'queued'})}

    monkeypatch.setattr(defectdojo, 'rpc', queued)
    first = await defectdojo.export('s', dojo.config)
    assert first['status'] == 'uncertain', _why(first)
    assert 'HTTP 202' in first['detail']

    # And it blocks: a later export of a CHANGED report must not paper over the
    # write whose outcome nobody established.
    monkeypatch.setattr(defectdojo, 'rpc', dojo.rpc)
    await put_finding(title='Changed while the first write was in flight')
    blocked = await defectdojo.export('s', dojo.config)
    assert blocked['id'] == first['id'], _why(blocked)
    assert blocked['status'] == 'uncertain'


async def test_a_rejected_initial_import_is_failed_and_does_not_block(dojo, monkeypatch):
    """A 4xx on the FIRST remote request wrote nothing, so it must not block.

    The `failed` downgrade in `export()` is scoped by `len(audit) == 2` — that is,
    the POST was the first remote call, which only happens for an initial import
    (a reimport reads the remote inventory first). See the companion test below
    for why that scoping matters.
    """
    await put_finding()
    cfg = defectdojo.ExportConfig(server='https://dojo.test', secret_id=dojo.secret,
                                  action='import', engagement_id=17, test_title='Client app')

    async def rejected(sandbox, request):
        dojo.calls.append(copy.deepcopy(request))
        return {'status': 400, 'body': 'no such engagement'}

    monkeypatch.setattr(defectdojo, 'rpc', rejected)
    result = await defectdojo.export('s', cfg)
    assert result['status'] == 'failed', _why(result)

    monkeypatch.setattr(defectdojo, 'rpc', dojo.rpc)
    retried = await defectdojo.export('s', cfg)
    assert retried['id'] != result['id'], "a failed export must not block the retry"
    assert retried['status'] == 'completed', _why(retried)


async def test_a_rejected_reimport_stays_uncertain_because_a_read_preceded_it(dojo, monkeypatch):
    """Pins the conservative asymmetry, so a reader of the docs is not surprised.

    A reimport into an existing test reads the remote inventory before writing,
    so a 4xx on its POST arrives with three audit entries rather than two and the
    `failed` downgrade does not apply — the export is `uncertain` and blocks,
    even though a 4xx means nothing was written.

    This is deliberately not "fixed" here. Treating it as `failed` would unblock
    the destination on the strength of inferring, from a status code the remote
    chose, that no partial processing occurred; blocking until someone looks is
    the safer default for a write to a client's tracker. It is recorded because
    the behaviour is asymmetric and nothing said so.
    """
    await put_finding()

    async def rejected_write(sandbox, request):
        if request.get('method', 'POST') != 'POST':
            return await dojo.rpc(sandbox, request)
        dojo.calls.append(copy.deepcopy(request))
        return {'status': 400, 'body': 'malformed report'}

    monkeypatch.setattr(defectdojo, 'rpc', rejected_write)
    result = await defectdojo.export('s', dojo.config)
    assert result['status'] == 'uncertain', _why(result)
    assert 'HTTP 400' in result['detail']


async def test_a_lost_first_import_does_not_block_a_direct_reimport(dojo, monkeypatch):
    """The narrowness of the block, pinned so it cannot change silently.

    docs/integrations.md used to promise that an uncertain write "blocks until
    someone looks". It does — but the block matches on destination, or on
    `remote_test_id` for that server, and a first `import` whose response was
    lost NEVER LEARNED a test ID. Its row carries `remote_test_id = NULL`, so
    `remote_test_id = ?` cannot match, and the operator who follows the doc's own
    advice — look the test up in the UI, then address it with
    `action: "reimport"` and its `test_id` — sails straight past the block and
    writes a changed report over a write nobody established.

    This test does not assert that the behaviour is right. It asserts what the
    behaviour IS, because the documentation now describes it and a reader will
    plan around it.
    """
    await put_finding()
    initial = defectdojo.ExportConfig(server='https://dojo.test', secret_id=dojo.secret,
                                      action='import', engagement_id=7, test_title='Client app')

    async def queued(sandbox, request):
        dojo.calls.append(copy.deepcopy(request))
        return {'status': 202, 'body': json.dumps({'message': 'queued'})}

    monkeypatch.setattr(defectdojo, 'rpc', queued)
    lost = await defectdojo.export('s', initial)
    assert lost['status'] == 'uncertain', _why(lost)
    assert lost['remote_test_id'] is None, "the premise: no test ID was ever learned"

    monkeypatch.setattr(defectdojo, 'rpc', dojo.rpc)
    # The same body IS blocked — same destination.
    assert (await defectdojo.export('s', initial))['id'] == lost['id']

    # Addressing the test directly is NOT.
    await put_finding(title='Changed while the first write was in flight')
    direct = defectdojo.ExportConfig(server='https://dojo.test', secret_id=dojo.secret,
                                     action='reimport', test_id=42)
    after = await defectdojo.export('s', direct)
    assert after['id'] != lost['id'], "if this now blocks, the docs need updating"
    assert after['status'] == 'completed', _why(after)
    assert [f['title'] for f in dojo.findings.values()] == ['Changed while the first write was in flight']


async def test_a_local_failure_before_any_request_is_uncertain_and_blocks(dojo, monkeypatch):
    """Zero requests sent, and the destination is blocked anyway.

    `export()` marks `uncertain` for any non-RemoteError exception, which
    includes ones raised before a single byte leaves the machine — the sandbox
    failing to start because Docker is down, or a cancelled run. Reconciliation
    cannot clear such a row: there is no remote write to verify against.

    Pinned because docs/integrations.md now warns operators about it. It is a
    sharp edge, recorded in docs/future-plan.md, not a design decision.
    """
    await put_finding()

    working = defectdojo.Sandbox      # the fixture's FakeSandbox

    class Exploding:
        def __init__(self, *a, **kw):
            raise RuntimeError('docker daemon not running')

    monkeypatch.setattr(defectdojo, 'Sandbox', Exploding)
    with pytest.raises(RuntimeError):
        await defectdojo.export('s', dojo.config)

    row = (await db.rows('SELECT * FROM integration_exports'))[0]
    assert row['status'] == 'uncertain', _why(row)
    assert row['detail'] == 'Check the remote test before retrying'
    assert not [c for c in dojo.calls if 'url' in c], "nothing should have been sent"

    # Restore only the sandbox: monkeypatch.undo() would also revert the
    # fixture's DB_PATH patch and the export would fail looking for its
    # assessment, which looks like a blocked export and is not one.
    monkeypatch.setattr(defectdojo, 'Sandbox', working)
    blocked = await defectdojo.export('s', dojo.config)
    assert blocked['id'] == row['id'], "the destination is blocked by a local failure"


async def test_reconcile_reports_a_remote_error_instead_of_a_bare_500(dojo, monkeypatch):
    """A diagnosable condition has to reach the operator to be diagnosable.

    `export()` catches RemoteError itself and records it on the export row, so
    reconciliation is the only path that lets one reach a caller — and
    RemoteError is a RuntimeError, which the route's
    `except (ValueError, FileNotFoundError, KeyError)` did not catch. The most
    likely one to land there is the actionable one: two remote findings sharing
    a fingerprint, which the operator must settle in DefectDojo before Erlik can
    map them. It arrived as HTTP 500 with no body.
    """
    from fastapi import HTTPException
    from orchestrator.integrations.api import reconcile_defectdojo

    await put_finding()
    await defectdojo.export('s', dojo.config)
    await db.execute("UPDATE integration_exports SET status='uncertain'")
    row = (await db.rows('SELECT * FROM integration_exports'))[0]

    async def duplicated(sandbox, request):
        if request.get('method', 'POST') == 'GET':
            one = dict(dojo.findings[1])
            return {'status': 200, 'body': json.dumps(
                {'results': [one, dict(one, id=99)], 'next': None})}
        return await dojo.rpc(sandbox, request)

    monkeypatch.setattr(defectdojo, 'rpc', duplicated)
    with pytest.raises(HTTPException) as exc:
        await reconcile_defectdojo(row['id'], dojo.config)
    assert exc.value.status_code == 502, "a remote that misbehaved is not our 500"
    assert 'share one fingerprint' in exc.value.detail
