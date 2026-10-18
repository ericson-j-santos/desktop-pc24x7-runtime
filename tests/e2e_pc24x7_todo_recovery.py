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
        # Full hosted orchestration with real local PostgreSQL and real sealing.
        # Only the GitHub transport and source configuration are simulated.
        import base64 as hosted_base64
        from unittest import mock as hosted_mock

        with hosted_mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            import todo_hosted_backup as hosted

        class MemoryDraftRelease:
            """Simulated GitHub transport; never performs network I/O."""

            def __init__(self):
                self.release = None
                self.assets = {}
                self.uploads = 0
                self.readbacks = 0

            def find_draft(self, tag):
                if self.release is None or self.release["tag_name"] != tag:
                    return None
                return dict(self.release)

            def get_release(self, release_id):
                assert self.release is not None and self.release["id"] == release_id
                return dict(self.release)

            def create_or_get_draft(self, tag, sha):
                if self.release is None:
                    self.release = {
                        "id": 73, "tag_name": tag, "target_commitish": sha, "draft": True,
                    }
                assert self.release["tag_name"] == tag
                return dict(self.release)

            def list_assets(self, release_id):
                self.get_release(release_id)
                return [dict(meta) for meta, _ in self.assets.values()]

            def upload(self, release_id, name, payload):
                self.get_release(release_id)
                assert not any(meta["name"] == name for meta, _ in self.assets.values())
                self.uploads += 1
                meta = {
                    "id": 100 + self.uploads, "name": name, "state": "uploaded",
                    "digest": "sha256:" + hosted.sha256(payload), "size": len(payload),
                }
                self.assets[meta["id"]] = (meta, bytes(payload))
                return dict(meta)

            def readback(self, asset, limit):
                self.readbacks += 1
                meta, payload = self.assets[asset["id"]]
                assert meta["name"] == asset["name"]
                return payload[:limit + 1]

        source_profile = r.service("todo_recovery_source", pg.env, target=False)
        assert source_profile["host"] == "127.0.0.1"
        assert source_profile["dbname"] == "todo_global_bus_dev_ha"
        assert r.fingerprint(pg, "todo_recovery_source") == source_before

        def local_hosted_config(worker_root, _worker_env, public_pem):
            # The private recovery key never enters the hosted worker directory.
            public_path = worker_root / "recipient.pem"
            public_path.write_bytes(public_pem)
            public_path.chmod(0o600)
            return dict(pg.env)

        producer_sha = os.environ["GITHUB_SHA"]
        recipient_sha = hosted.key_id(key.public_key())
        hosted_env = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": hosted.EXPECTED_REPO,
            "GITHUB_SHA": producer_sha, "GITHUB_TOKEN": "synthetic-invalid-no-network-token",
            "TODO_BACKUP_PG_PASSWORD": "synthetic-lab-password-unused",
            "TODO_BACKUP_RECIPIENT_PEM_B64": hosted_base64.b64encode(
                recipient.read_bytes()
            ).decode("ascii"),
            "TODO_BACKUP_RECIPIENT_SHA256": recipient_sha,
            "TODO_BACKUP_CUSTODY_APPROVAL": "offhost-key-verified",
        }
        hosted_transport = MemoryDraftRelease()

        # A midnight crossing must not change the identity of this same-day replay.
        frozen_time = hosted.datetime.now(hosted.timezone.utc)
        with hosted_mock.patch.object(hosted, "datetime", wraps=hosted.datetime) as hosted_clock:
            hosted_clock.now.return_value = frozen_time
            with hosted_mock.patch.object(
                hosted, "build_source_config", side_effect=local_hosted_config,
            ) as config_spy:
                hosted_first = hosted.run(hosted_env, hosted_transport, bin_dir=binary)
            assert config_spy.call_count == 1
            assert hosted_first["state"] == "encrypted_draft_uploaded"
            assert hosted_first["source_sha"] == producer_sha
            assert hosted_first["source_major"] == 18
            assert hosted_first["production_data_read"] is True
            assert hosted_first["source_rows"] == 4
            assert hosted_first["database_restore_verified"] is False

            # Verification metadata must not overwrite the original producer.
            replay_sha = "b" * 40 if producer_sha != "b" * 40 else "c" * 40
            with (
                hosted_mock.patch.object(
                    hosted, "build_source_config",
                    side_effect=AssertionError("HOSTED_REPLAY_RECONNECTED"),
                ),
                hosted_mock.patch.object(
                    hosted, "Postgres",
                    side_effect=AssertionError("HOSTED_REPLAY_POSTGRES_CREATED"),
                ),
                hosted_mock.patch.object(
                    hosted, "capture",
                    side_effect=AssertionError("HOSTED_REPLAY_RECAPTURED"),
                ),
            ):
                hosted_replay = hosted.run(
                    {**hosted_env, "GITHUB_SHA": replay_sha},
                    hosted_transport, bin_dir=binary,
                )

        assert hosted_replay["state"] == "already_verified"
        assert hosted_replay["source_sha"] is None and hosted_replay["source_db"] is None
        assert hosted_replay["release_producer_sha"] == producer_sha
        assert hosted_replay["executor_sha"] == replay_sha
        assert hosted_replay["capture_executed"] is False
        assert hosted_replay["production_data_read"] is False
        assert hosted_replay["replay_without_source_access"] is True
        assert hosted_transport.uploads == 1 and len(hosted_transport.assets) == 1

        # Retrieve the ciphertext AFTER run() has removed its capture directory.
        # Restore below receives only bytes downloaded from this transport.
        stored_asset = next(
            asset for asset in hosted_transport.list_assets(hosted_first["release_id"])
            if asset["id"] == hosted_first["asset_id"]
        )
        downloaded = hosted_transport.readback(stored_asset, hosted.MAX_ARCHIVE)
        assert len(downloaded) == stored_asset["size"]
        assert hosted.sha256(downloaded) == hosted_first["ciphertext_sha256"]
        assert hosted_transport.readbacks >= 3

        hosted_envelope = root / "hosted-downloaded.sealed"
        hosted_envelope.write_bytes(downloaded)
        hosted_bundle = root / "hosted-unsealed"
        hosted_rc, hosted_opened = sealed_cli(
            "unseal", hosted_envelope, hosted_bundle, hosted_first["ciphertext_sha256"],
        )
        assert hosted_rc == 0 and hosted_opened["state"] == "unsealed"
        hosted_manifest = r.bundle_manifest(hosted_bundle)
        assert hosted_manifest["tables"] == source_before
        assert hosted_manifest["producer_sha"] == producer_sha

        # A distinct empty database prevents reuse of the earlier restore.
        hosted_database = "todo_restore_hosted_lab"
        assert admin(
            "SELECT count(*) FROM pg_database WHERE datname='todo_restore_hosted_lab'"
        ) == "0"
        admin("CREATE DATABASE todo_restore_hosted_lab OWNER todo_recovery_owner")
        hosted_services = root / "hosted_restore_service.conf"
        original_services = services.read_text(encoding="utf-8")
        assert original_services.count("dbname=todo_restore_lab\n") == 1
        hosted_services.write_text(
            original_services.replace(
                "dbname=todo_restore_lab\n", "dbname=todo_restore_hosted_lab\n",
            ), encoding="utf-8",
        )
        hosted_services.chmod(0o600)
        hosted_pg = r.Postgres(binary, {**pg.env, "PGSERVICEFILE": str(hosted_services)})
        hosted_restored = r.restore(
            hosted_pg, hosted_bundle, hosted_manifest["correlation_id"],
        )
        assert hosted_restored["state"] == "verified"
        assert hosted_restored["rows_verified"] == 4
        assert hosted_restored["cutover_ready"] is False

        # The newer capture contains 3 queue rows + 1 request, including late-event.
        # Restoring the older bundle (2 + 1) would fail these independent queries.
        assert admin("SELECT count(*) FROM todo_bus.queue_events", hosted_database) == "3"
        assert admin(
            "SELECT count(*) FROM todo_bus.continuation_requests", hosted_database,
        ) == "1"
        assert admin(
            "SELECT state FROM todo_bus.queue_events WHERE event_id='late-event'",
            hosted_database,
        ) == "PENDING"
        assert r.fingerprint(hosted_pg, "todo_recovery_target") == source_before
        assert r.fingerprint(pg, "todo_recovery_source") == source_before

        hosted_drill = {
            "hosted_orchestration_local_pg18_verified": True,
            "hosted_capture_seal_download_unseal_restore": True,
            "hosted_restored_rows": 4,
            "hosted_replay_without_source_reconnect": True,
            "hosted_replay_preserves_release_revision": True,
            "hosted_replay_does_not_claim_source_provenance": True,
            "hosted_decrypted_manifest_producer_verified": True,
            "hosted_transport": "in_memory_fake_release",
            "hosted_source_config": "loopback_synthetic_lab_override",
            "external_storage_verified": False,
        }
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
        receipt.update(hosted_drill)
        (ROOT/'recovery-e2e-receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
        print(json.dumps(receipt,sort_keys=True))
    finally:
        if started:run(['gosu','postgres',str(binary/'pg_ctl'),'-D',str(data),'-m','fast','-w','stop'])
    return 0


if __name__=='__main__':raise SystemExit(main())
