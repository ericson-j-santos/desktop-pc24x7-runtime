"""Deterministic safety controls; real PostgreSQL is tested in the separate E2E."""
from __future__ import annotations
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import pytest

MODULE = Path(__file__).resolve().parents[1] / 'scripts/pc24x7_todo_recovery.py'
spec = importlib.util.spec_from_file_location('pc24x7_todo_recovery_tests', MODULE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

@pytest.fixture
def setup(tmp_path):
    profiles = tmp_path/'services.conf'
    profiles.write_text('[todo_recovery_source]\nhost=127.0.0.1\nport=55433\ndbname=todo_global_bus_dev_ha\nuser=test\n'
        '[todo_recovery_target]\nhost=127.0.0.1\nport=55433\ndbname=todo_restore_lab\nuser=test\n')
    passwords = tmp_path/'pgpass'
    passwords.write_text('')
    passwords.chmod(0o600)
    bundle = tmp_path/'bundle'
    bundle.mkdir(mode=0o700)
    return {'PGSERVICEFILE':str(profiles),'PGPASSFILE':str(passwords)},bundle


def manifest():
    return {'schema_version':1,'source_major':18,'archive_sha256':'a'*64,
        'correlation_id':'recovery-test','tables':{
            'queue_events':{'rows':109,'sha256':'b'*64},
            'continuation_requests':{'rows':50,'sha256':'c'*64}},'cutover_ready':False}


def make_bundle(bundle):
    (bundle/'database.dump').write_bytes(b'PGDMP-unit-fixture-not-real-postgres')
    value=manifest();value['archive_sha256']=r.digest_file(bundle/'database.dump')
    (bundle/'manifest.json').write_bytes(r.canonical(value))
    return value


class FakePg:
    def __init__(self,env,tables):
        self.env=env;self.tables=tables;self.calls=[];self.occupied=0
        self.version=18;self.superuser=False;self.restored=False
    def major(self,tool):return self.version
    def sql(self,alias,query,**kwargs):
        if query==r.IDENTITY_SQL:return {'database':'todo_restore_lab' if 'target' in alias else 'todo_global_bus_dev_ha','major':self.version,'superuser':self.superuser}
        if query==r.TABLES_SQL:return sorted(self.tables)
        if query.startswith('SELECT count(*) FROM pg_class'):return self.occupied
        for name,item in self.tables.items():
            if f'"{name}"' in query:return copy.deepcopy(item)
        raise AssertionError(query)
    def run(self,tool,*args,**kwargs):
        self.calls.append((tool,args,kwargs))
        if tool=='pg_dump':
            output=next(x.split('=',1)[1] for x in args if x.startswith('--file='))
            Path(output).write_bytes(b'PGDMP-unit-fixture')
        self.restored=tool=='pg_restore'
        return ''
    @contextlib.contextmanager
    def snapshot(self,alias):yield '00000001-00000002-1'


def test_positive_restore_and_idempotent_readback(setup):
    env,bundle=setup;value=make_bundle(bundle);pg=FakePg(env,value['tables'])
    first=r.restore(pg,bundle,'recovery-test')
    second=r.restore(pg,bundle,'recovery-test')
    assert first['state']=='verified' and second['state']=='already_verified'
    assert first['rows_verified']==159 and not first['cutover_ready']
    assert not first['workers_started'] and not second['restore_executed']
    assert len(pg.calls)==1 and pg.calls[0][0]=='pg_restore'
    args=pg.calls[0][1]
    assert '--single-transaction' in args and '--exit-on-error' in args
    assert '--clean' not in args and '--create' not in args


def test_capture_and_replay_preserve_original_bundle(setup):
    env,bundle=setup;pg=FakePg(env,manifest()['tables'])
    result=r.capture(pg,bundle,'recovery-test')
    assert result['state']=='captured'
    before=(bundle/'manifest.json').read_bytes()
    assert r.capture(pg,bundle,'recovery-test')['state']=='already_captured'
    assert (bundle/'manifest.json').read_bytes()==before and len(pg.calls)==1
    args=pg.calls[0][1]
    assert '--snapshot=00000001-00000002-1' in args and pg.calls[0][2]['readonly']

@pytest.mark.parametrize('change,reason',[
    ({'source_major':True},'SOURCE_MAJOR'),({'source_major':19},'SOURCE_MAJOR'),
    ({'archive_sha256':'bad'},'MANIFEST'),({'schema_version':2},'MANIFEST'),
    ({'schema_version':True},'MANIFEST'),
    ({'tables':{}},'REQUIRED'),({'tables':{'queue_events':{'rows':0,'sha256':'a'*64},'continuation_requests':{'rows':0,'sha256':'b'*64}}},'EMPTY_SOURCE')])
def test_manifest_rejects_invalid_or_empty_source(change,reason):
    value=manifest();value.update(change)
    with pytest.raises(r.RecoveryBlocked,match=reason):r.validate_manifest(value)

@pytest.mark.parametrize('field,value', [('rows',True),('rows',-1),('rows','109'),('sha256','oops')])
def test_invalid_table_fingerprint(field,value):
    data=manifest();data['tables']['queue_events'][field]=value
    with pytest.raises(r.RecoveryBlocked,match='MANIFEST'):r.validate_manifest(data)

@pytest.mark.parametrize('old,new,reason',[
    ('dbname=todo_restore_lab','dbname=todo_global_bus_dev','ISOLATED'),
    ('dbname=todo_restore_lab','dbname=todo_restore_lab;drop','DATABASE'),
    ('host=127.0.0.1','host=database.example','ISOLATED'),
    ('port=55433','port=0','PORT'),
    ('user=test','user=test\npassword=not-allowed','PROFILE')])
def test_service_target_controls(setup,old,new,reason):
    env,_=setup;path=Path(env['PGSERVICEFILE']);path.write_text(path.read_text().replace(old,new))
    with pytest.raises(r.RecoveryBlocked,match=reason):r.service('todo_recovery_target',env,target=True)


def test_remote_source_must_verify_tls(setup):
    env,_=setup;path=Path(env['PGSERVICEFILE']);path.write_text(path.read_text().replace('host=127.0.0.1','host=source.example',1))
    with pytest.raises(r.RecoveryBlocked,match='TLS'):r.service('todo_recovery_source',env,target=False)

@pytest.mark.parametrize('problem,reason', [('older','TOO_OLD'),('occupied','NOT_EMPTY'),('admin','NON_SUPERUSER'),('digest','DIGEST'),('correlation','CORRELATION')])
def test_blocks_before_restore_without_side_effects(setup,problem,reason):
    env,bundle=setup;value=make_bundle(bundle);pg=FakePg(env,value['tables'])
    if problem=='older':pg.version=16
    if problem=='occupied':pg.occupied=1
    if problem=='admin':pg.superuser=True
    if problem=='digest':(bundle/'database.dump').write_bytes(b'PGDMP-corrupt')
    correlation='different' if problem=='correlation' else 'recovery-test'
    with pytest.raises(r.RecoveryBlocked,match=reason):r.restore(pg,bundle,correlation)
    assert pg.calls==[]


def test_drift_rejects_false_replay(setup):
    env,bundle=setup;value=make_bundle(bundle);pg=FakePg(env,value['tables'])
    r.restore(pg,bundle,'recovery-test');pg.tables['queue_events']['rows']+=1
    with pytest.raises(r.RecoveryBlocked,match='DRIFT'):r.restore(pg,bundle,'recovery-test')
    assert len(pg.calls)==1


def test_busy_lock_not_removed_or_retried(setup):
    _,bundle=setup;lock=bundle/'.operation.lock';lock.write_text('other-executor')
    with pytest.raises(r.RecoveryBlocked,match='BUSY'):
        with r.exclusive(bundle):raise AssertionError('must not enter')
    assert lock.read_text()=='other-executor'


def test_partial_backup_not_overwritten(setup):
    env,bundle=setup;(bundle/'database.dump.part').write_bytes(b'partial')
    with pytest.raises(r.RecoveryBlocked,match='PARTIAL'):
        r.capture(FakePg(env,manifest()['tables']),bundle,'recovery-test')
    assert (bundle/'database.dump.part').read_bytes()==b'partial'


def test_sensitive_libpq_environment_is_not_inherited(setup):
    env,_=setup;env.update(PGPASSWORD='private',PGHOST='wrong-host',PGOPTIONS='bad',PGDATABASE='production')
    pg=r.Postgres(Path('/bin'),env)
    assert 'PGPASSWORD' not in pg.env and 'PGHOST' not in pg.env
    assert 'PGOPTIONS' not in pg.env and 'PGDATABASE' not in pg.env


def test_sql_and_transport_errors_do_not_leak(setup,monkeypatch):
    env,_=setup;pg=r.Postgres(Path('/bin'),env)
    monkeypatch.setattr(pg,'command',lambda *args:['fake'])
    monkeypatch.setattr(subprocess,'run',lambda *args,**kwargs:subprocess.CompletedProcess([],1,'','password=private'))
    with pytest.raises(r.RecoveryBlocked,match='POSTGRES_COMMAND_FAILED') as error:pg.run('psql')
    assert 'private' not in str(error.value)


def test_missing_service_secret_reference_blocks(setup):
    env,_=setup;env.pop('PGPASSFILE')
    with pytest.raises(r.RecoveryBlocked,match='PASSWORD_FILE_REQUIRED'):r.service('todo_recovery_target',env,target=True)


def test_real_command_cli_cannot_accept_production_action():
    text=MODULE.read_text()
    assert 'choices=("capture", "verify-restore")' in text
    assert 'shell=True' not in text
    assert '"dropdb"' not in text and '"createdb"' not in text


def test_recovery_compose_is_separate_and_never_starts_consumers():
    text=(MODULE.parents[1]/'docker-compose.todo-recovery.yml').read_text()
    assert '127.0.0.1:55433:5432' in text
    assert 'name: todo_recovery_pg18' in text
    assert 'todo_global_pgdata' not in text
    assert '/var/lib/postgresql/18/docker' in text
    assert 'POSTGRES_PASSWORD_FILE:' in text
    assert 'POSTGRES_PASSWORD:' not in text and 'POSTGRES_HOST_AUTH_METHOD:' not in text
    assert 'restart: "no"' in text
    assert not any(f'  {name}:' in text for name in ('gateway','worker','ingest'))
    assert '@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336' in text


def test_e2e_workflow_has_no_physical_or_provider_access():
    text=(MODULE.parents[1]/'.github/workflows/todo-recovery-isolated-e2e.yml').read_text()
    assert 'runs-on: ubuntu-latest' in text and 'contents: read' in text
    assert 'TODO_RECOVERY_LAB: synthetic-only' in text
    assert 'persist-credentials: false' in text
    assert 'recovery-e2e-receipt.json' in text
    assert not any(x in text for x in ('self-hosted', 'secrets.', 'workflow_dispatch:', 'id-token: write'))


def test_snapshot_injection_and_restore_count_ignore_version_commands():
    text=(MODULE.parents[1]/'tests/e2e_pc24x7_todo_recovery.py').read_text()
    assert "tool=='pg_dump' and '--version' not in args" in text
    assert 'if "--version" not in args:' in text
