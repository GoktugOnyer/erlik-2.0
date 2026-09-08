"""Actual pinned DefectDojo service acceptance, opt-in and entirely local.

Run ERLIK_DEFECTDOJO_LIVE_TESTS=1 pytest -q tests/test_defectdojo_live.py.
The fixture starts a private disposable Compose deployment, imports through
Erlik's isolated HTTP proxy, and deletes only its own deployment at teardown.
"""
import asyncio
import json
import os
import secrets
import subprocess
import uuid
from pathlib import Path
import pytest
from orchestrator.integrations import defectdojo, persistence as db, service
from orchestrator.integrations.runtime import docker, Sandbox
from orchestrator.integrations.adapters import rpc
from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.security import SecretStore, private_write

pytestmark = [pytest.mark.docker, pytest.mark.skipif(os.environ.get('ERLIK_DEFECTDOJO_LIVE_TESTS') != '1', reason='set ERLIK_DEFECTDOJO_LIVE_TESTS=1 for actual DefectDojo service acceptance')]
LAB = Path(__file__).resolve().parents[1] / 'docker' / 'defectdojo-lab'


def _export_state(row):
    """status plus the detail that explains it.

    `assert row['status'] == 'completed', row` truncates the row in pytest's
    output, and `detail` — the only field that says WHY a write went uncertain
    — is what gets elided. Report the two fields that matter.
    """
    return f"status={row['status']!r} detail={row.get('detail')!r}"


@pytest.fixture
async def live_dojo(tmp_path, monkeypatch):
    import orchestrator.database as original
    project = 'erlik-dojo-' + uuid.uuid4().hex[:10]
    network = project + '-network'
    cert_dir = tmp_path / 'tls'
    cert_dir.mkdir(mode=0o700)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(cert_dir / 'nginx.key'), '-out', str(cert_dir / 'nginx.crt'),
                    '-subj', '/CN=dojo.test', '-addext', 'subjectAltName=DNS:dojo.test'], check=True, capture_output=True)
    # Nginx runs as UID 1001; private containing directory stays mode 0700.
    (cert_dir / 'nginx.key').chmod(0o644)
    env_path = tmp_path / 'dojo.env'
    private_write(env_path, '\n'.join(f'{k}={v}' for k, v in {
        'ERLIK_DOJO_DB_PASSWORD': secrets.token_hex(16), 'ERLIK_DOJO_SECRET': secrets.token_hex(32),
        'ERLIK_DOJO_AES_KEY': secrets.token_hex(16), 'ERLIK_DOJO_ADMIN_PASSWORD': secrets.token_hex(24),
        'ERLIK_DOJO_CERT_DIR': str(cert_dir), 'ERLIK_DOJO_NETWORK': network}.items()))
    command = ['compose', '-p', project, '--env-file', str(env_path), '-f', str(LAB / 'compose.yml')]
    monkeypatch.setenv('ERLIK_INTEGRATION_EGRESS_NETWORK', network)
    monkeypatch.setenv('ERLIK_INTEGRATION_CA_FILE', str(cert_dir / 'nginx.crt'))
    monkeypatch.setenv('ERLIK_INTEGRATION_DATA', str(tmp_path / 'runtime'))
    monkeypatch.setattr(original, 'DB_DIR', tmp_path)
    monkeypatch.setattr(original, 'DB_PATH', tmp_path / 'test.db')
    await original.init_db()
    await db.migrate()
    try:
        await docker(*command, 'up', '-d', timeout=600)
        _, uwsgi, _ = await docker(*command, 'ps', '-q', 'uwsgi')
        # Use ORM only to create the existing engagement and service credentials.
        # Every operation under test below goes through the real HTTP API.
        setup = '''from datetime import date
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from dojo.models import Product_Type, Product, Engagement
import json
user=User.objects.get(username='erlik-lab')
token=Token.objects.get_or_create(user=user)[0].key
pt=Product_Type.objects.create(name='Erlik fixture')
p=Product.objects.create(name='Erlik local lab', description='Disposable acceptance fixture', prod_type=pt)
e=Engagement.objects.create(name='Erlik integration acceptance', product=p, target_start=date.today(), target_end=date.today(), status='In Progress')
print('ERLIK_LAB_RESULT='+json.dumps({'token':token,'engagement_id':e.pk}))'''
        # Retry only this read-only readiness check, never an import/write.
        for _ in range(60):
            code, _, _ = await docker('exec', uwsgi.strip(), 'python', '-c',
                "import urllib.request;urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8081/login', headers={'Host':'dojo.test'}))", check=False)
            if code == 0: break
            await asyncio.sleep(1)
        else:
            raise RuntimeError('DefectDojo did not become ready')
        _, output, _ = await docker('exec', uwsgi.strip(), 'python', 'manage.py', 'shell', '-c', setup, timeout=60)
        data = json.loads(next(line.split('=', 1)[1] for line in output.splitlines() if line.startswith('ERLIK_LAB_RESULT=')))
        data['secret_id'] = SecretStore().put({'token': data.pop('token')})
        yield data
    finally:
        await docker(*command, 'down', '--volumes', '--remove-orphans', timeout=90, check=False)


async def test_actual_defectdojo_import_reimport_update_partial_and_triage(live_dojo):
    config = AssessmentConfig(scope={'allow_hosts': ['app.test'], 'allow_ports': [443]}, stages=['zap'],
                              budget={'stage_seconds': 120, 'assessment_seconds': 300})
    await service.register('live-dojo', 'https://app.test', config)
    async def finding(fp, **overrides):
        value = dict(fingerprint=fp, title='Fixture finding', basis='Controlled deterministic evidence',
                     severity='medium', confidence='likely', url='https://app.test/private', triage_state='open')
        value.update(overrides)
        await db.execute('INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)', ('live-dojo', fp, json.dumps(value)))
    await finding('a' * 64)
    await finding('b' * 64)  # Same title and endpoint, distinct authorization context.
    cfg = defectdojo.ExportConfig(server='https://dojo.test:8443', secret_id=live_dojo['secret_id'], action='import',
                                  engagement_id=live_dojo['engagement_id'], test_title='Erlik lab acceptance')
    first = await defectdojo.export('live-dojo', cfg)
    assert first['status'] == 'completed', _export_state(first)
    assert first['remote_test_id'] > 0
    second = await defectdojo.export('live-dojo', cfg)
    assert first['id'] == second['id']
    mappings = await db.rows('SELECT * FROM integration_remote_findings ORDER BY fingerprint')
    assert len(mappings) == 2 and len({r['remote_finding_id'] for r in mappings}) == 2
    await finding('a' * 64, title='Changed finding title', basis='Additional controlled evidence', severity='high')
    changed = await defectdojo.export('live-dojo', cfg)
    assert changed['status'] == 'completed', _export_state(changed)
    assert (await db.rows('SELECT * FROM integration_remote_findings ORDER BY fingerprint'))[0]['remote_finding_id'] == mappings[0]['remote_finding_id']
    # A partial run omits one item; omission must leave that remote finding open.
    await db.execute("UPDATE integration_assessments SET status='partial'")
    await db.execute('DELETE FROM integration_findings WHERE fingerprint=?', ('b' * 64,))
    partial = await defectdojo.export('live-dojo', cfg)
    assert partial['status'] == 'completed', _export_state(partial)
    token = SecretStore().get(live_dojo['secret_id'])['token']
    async with Sandbox(config, services=[cfg.server]) as sandbox:
        inventory = await defectdojo.remote_inventory(sandbox, cfg, token, [], first['remote_test_id'])
    assert len(inventory) == 2
    assert inventory['a' * 64]['title'].casefold() == 'Changed finding title'.casefold()
    assert inventory['a' * 64]['severity'] == 'High'
    assert inventory['b' * 64]['active'] is True and inventory['b' * 64]['is_mitigated'] is False
    await finding('a' * 64, triage_state='false_positive', confidence='confirmed')
    triaged = await defectdojo.export('live-dojo', cfg)
    assert triaged['status'] == 'completed', _export_state(triaged)
    async with Sandbox(config, services=[cfg.server]) as sandbox:
        inventory = await defectdojo.remote_inventory(sandbox, cfg, token, [], first['remote_test_id'])
    assert inventory['a' * 64]['false_p'] and not inventory['a' * 64]['active'] and not inventory['a' * 64]['verified']
    report_path = os.environ.get('ERLIK_DEFECTDOJO_RESULT')
    if report_path:
        private_write(Path(report_path), json.dumps({'version': '2.58.4', 'initial_import': True, 'unchanged_no_duplicates': True,
            'distinct_contexts_preserved': True, 'changed_updates_same_id': True, 'partial_does_not_close': True,
            'local_triage_propagated': True, 'remote_test_id': first['remote_test_id'],
            'remote_finding_ids': [r['remote_finding_id'] for r in mappings]}, indent=2))
