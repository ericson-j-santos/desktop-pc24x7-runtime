"""Real PG18 drill. Synthetic data only, inside the isolated CI job container."""
from __future__ import annotations
import importlib.util
import json
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery_e2e',ROOT/'scripts/pc24x7_todo_recovery.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def main():
    if os.environ.get('TODO_RECOVERY_LAB')!='synthetic-only' or os.environ.get('GITHUB_ACTIONS')!='true':
        raise RuntimeError('ISOLATED_CI_LAB_REQUIRED')
    binary=Path('/usr/lib/postgresql/18/bin')
    root=Path(tempfile.mkdtemp(prefix='todo-recovery-lab-'))
    uid=pwd.getpwnam('postgres').pw_uid;gid=pwd.getpwnam('postgres').pw_gid
    os.chown(root,uid,gid);root.chmod(0o700)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    data=root/'pgdata'
    def run(args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=120,check=False)
        if result.returncode:raise RuntimeError('SYNTHETIC_LAB_COMMAND_FAILED: '+result.stderr[-600:])
        return result.stdout.strip()
    run(['gosu','postgres',str(binary/'initdb'),'-D',str(data),'--auth-local=trust','--auth-host=trust','--no-locale','--encoding=UTF8'])
    started=False
    try:
        run(['gosu','postgres',str(binary/'pg_ctl'),'-D',str(data),'-l',str(root/'server.log'),'-o',f'-h 127.0.0.1 -p {port} -k {root}','-w','start'])
        started=True
        def admin(sql,database='postgres'):
            return run([str(binary/'psql'),'-X','-qAt','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',str(port),'-U','postgres','-d',database,'-c',sql])
        admin('CREATE ROLE todo_recovery_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE')
        admin('CREATE DATABASE todo_global_bus_dev_ha OWNER todo_recovery_owner')
        admin('CREATE DATABASE todo_restore_lab OWNER todo_recovery_owner')
        source='todo_global_bus_dev_ha'
        admin("SET ROLE todo_recovery_owner; CREATE SCHEMA todo_bus; CREATE TABLE todo_bus.queue_events(event_id text PRIMARY KEY, state text NOT NULL, payload jsonb NOT NULL); CREATE TABLE todo_bus.continuation_requests(request_id text PRIMARY KEY, event_id text REFERENCES todo_bus.queue_events(event_id), state text NOT NULL); INSERT INTO todo_bus.queue_events VALUES ('event-1','PENDING','{\"text\":\"dados sintéticos\"}'),('event-2','PENDING','{\"nullable\":null}'); INSERT INTO todo_bus.continuation_requests VALUES ('request-1','event-1','HUMAN_GATE');",source)
        services=root/'pg_service.conf'
        services.write_text(
            f'[todo_recovery_source]\nhost=127.0.0.1\nport={port}\n'
            f'dbname={source}\nuser=todo_recovery_owner\n'
            f'[todo_recovery_target]\nhost=127.0.0.1\nport={port}\n'
            'dbname=todo_restore_lab\nuser=todo_recovery_owner\n'
        )
        passwords=root/'pgpass';passwords.write_text('');passwords.chmod(0o600)
        pg=r.Postgres(binary,{'PGSERVICEFILE':str(services),'PGPASSFILE':str(passwords)})
        bundle=root/'backup'
        original_run=pg.run;commands=[];injected=False
        def observed_run(tool,*args,**kwargs):
            nonlocal injected
            if "--version" not in args:
                commands.append(tool)
            if tool=='pg_dump' and '--version' not in args and not injected:
                # A committed source write AFTER export_snapshot must not enter the dump.
                admin("INSERT INTO todo_bus.queue_events VALUES ('late-event','PENDING','{}')",source)
                injected=True
            return original_run(tool,*args,**kwargs)
        pg.run=observed_run
        captured=r.capture(pg,bundle,'todo-recovery-ci')
        manifest=r.bundle_manifest(bundle)
        assert manifest['tables']['queue_events']['rows']==2
        assert r.fingerprint(pg,'todo_recovery_source')['queue_events']['rows']==3
        source_before=r.fingerprint(pg,'todo_recovery_source')
        # Exercise the actual CLI and portable encrypted transport before pg_restore.
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        recipient = root/'recipient.pem'
        identity = root/'identity.pem'
        recipient.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        identity.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        identity.chmod(0o600)
        env = {**os.environ, 'TODO_RECOVERY_RECIPIENT_FILE': str(recipient),
               'TODO_RECOVERY_IDENTITY_FILE': str(identity)}
        def sealed_cli(action, src, dst, expected=None):
            args=[sys.executable,str(ROOT/'scripts/pc24x7_todo_sealed.py'),action,
                  '--source',str(src),'--destination',str(dst)]
            if expected is not None:
                args.extend(['--expected-sha256',expected])
            result=subprocess.run(args,env=env,text=True,capture_output=True,timeout=30)
            return result.returncode,json.loads(result.stdout)
        envelope=root/'backup.sealed'
        rc,sealed=sealed_cli('seal',bundle,envelope)
        assert rc==0 and sealed['state']=='sealed'
        sealed_hash=sealed['ciphertext_sha256']
        encrypted=envelope.read_bytes()
        assert b'PRIVATE KEY' not in encrypted and b'PGDMP' not in encrypted
        assert sealed_cli('seal',bundle,envelope)[1]['state']=='already_sealed'
        assert envelope.read_bytes()==encrypted
        transported=root/'transported.sealed'
        shutil.copyfile(envelope,transported)
        reopened=root/'reopened'
        rc,opened=sealed_cli('unseal',transported,reopened,sealed_hash)
        assert rc==0 and opened['state']=='unsealed'
        assert (reopened/'database.dump').read_bytes()==(bundle/'database.dump').read_bytes()
        assert (reopened/'manifest.json').read_bytes()==(bundle/'manifest.json').read_bytes()
        assert sealed_cli('unseal',transported,reopened,sealed_hash)[1]['state']=='already_unsealed'
        changed=root/'changed.sealed'
        changed.write_bytes(encrypted[:-1]+bytes([encrypted[-1]^1]))
        rejected=root/'must-not-exist'
        rc,bad=sealed_cli('unseal',changed,rejected,sealed_hash)
        assert rc==2 and bad['reason']=='CIPHERTEXT_DIGEST_MISMATCH' and not rejected.exists()
        # Pin the modified hash deliberately to test AEAD, independently of the outer hash.
        rc,bad=sealed_cli('unseal',changed,rejected,r.digest_file(changed))
        assert rc==2 and bad['reason']=='AUTHENTICATION_FAILED' and not rejected.exists()
        # Subsequent PostgreSQL restore reads ONLY the decrypted transported bundle.
        bundle=reopened
        first=r.restore(pg,bundle,'todo-recovery-ci')
        assert first['rows_verified']==3 and first['state']=='verified'
        assert admin('SELECT count(*) FROM todo_bus.queue_events', 'todo_restore_lab') == '2'
        assert admin('SELECT count(*) FROM todo_bus.continuation_requests', 'todo_restore_lab') == '1'
        assert not first['cutover_ready'] and not first['workers_started']
        restore_calls=commands.count('pg_restore')
        second=r.restore(pg,bundle,'todo-recovery-ci')
        assert second['state']=='already_verified' and not second['restore_executed']
        assert commands.count('pg_restore')==restore_calls
        assert source_before==r.fingerprint(pg,'todo_recovery_source')
        corrupt=root/'corrupt';shutil.copytree(bundle,corrupt);corrupt.chmod(0o700)
        with (corrupt/'database.dump').open('ab') as file:file.write(b'corruption')
        try:r.restore(pg,corrupt,'todo-recovery-ci')
        except r.RecoveryBlocked as error:assert str(error)=='ARCHIVE_DIGEST_MISMATCH'
        else:raise AssertionError('corrupt dump accepted')
        assert commands.count('pg_restore')==restore_calls
        admin("UPDATE todo_bus.queue_events SET state='CHANGED' WHERE event_id='event-1'",'todo_restore_lab')
        try:r.restore(pg,bundle,'todo-recovery-ci')
        except r.RecoveryBlocked as error:assert str(error)=='RESTORED_DATA_DRIFT'
        else:raise AssertionError('drift accepted')
        assert commands.count('pg_restore')==restore_calls
        receipt={'state':'lab_verified','postgres_major':18,'source_sha':os.environ.get('GITHUB_SHA'),
            'snapshot_excludes_late_source_write':True,'restore_data_verified':True,'replay_no_restore':True,
            'corrupt_archive_rejected':True,'target_drift_rejected':True,'source_preserved':True,
            'real_user_data_used':False,'physical_pdq_verified':False,'cutover_ready':False,
            'encrypted_transport_roundtrip':True,'seal_unseal_replay_no_rewrite':True,
            'tamper_rejected_before_plaintext':True,'restored_from_decrypted_transport':True,
            'external_storage_verified':False}
        (ROOT/'recovery-e2e-receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
        print(json.dumps(receipt,sort_keys=True))
    finally:
        if started:run(['gosu','postgres',str(binary/'pg_ctl'),'-D',str(data),'-m','fast','-w','stop'])
    return 0


if __name__=='__main__':raise SystemExit(main())
