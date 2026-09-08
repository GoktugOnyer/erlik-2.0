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
