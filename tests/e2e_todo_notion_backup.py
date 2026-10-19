"""Native PostgreSQL 18 drill of Notion backup and recovery; synthetic source/store only."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from pc24x7_todo_recovery import Postgres
from pc24x7_todo_sealed import SealedBlocked
import todo_notion_hosted_backup as hosted
import todo_notion_restore as recovery
from notion_snapshot_fixture import SyntheticNotionClient, synthetic_snapshot
from notion_backup_test_support import (
    CountingClient, FakeDraftTransport, NeverClient, hosted_env, key_material,
)


def main():
    if (os.environ.get("TODO_NOTION_LAB") != "synthetic-only" or
            os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0):
        raise RuntimeError("NATIVE_SYNTHETIC_NOTION_LAB_REQUIRED")
    producer_sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", producer_sha):
        raise RuntimeError("LAB_PRODUCER_SHA_REQUIRED")
    binary = Path("/usr/lib/postgresql/18/bin")
    root = Path(tempfile.mkdtemp(prefix="todo-notion-native-lab-"))
    owner = pwd.getpwnam("postgres")
    os.chown(root, owner.pw_uid, owner.pw_gid)
    root.chmod(0o700)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    data = root / "pgdata"
    safe_env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}

    def execute(args, *, input=None, env=None):
        result = subprocess.run(args, input=input, capture_output=True, text=True,
                                encoding="utf-8", timeout=150, env=env or safe_env,
                                check=False)
        if result.returncode:
            raise RuntimeError("SYNTHETIC_NOTION_LAB_COMMAND_FAILED")
        return result.stdout.strip()

    started = False
    try:
        execute(["gosu", "postgres", str(binary / "initdb"), "-D", str(data),
                 "--auth-local=trust", "--auth-host=trust", "--no-locale", "--encoding=UTF8"])
        execute(["gosu", "postgres", str(binary / "pg_ctl"), "-D", str(data),
                 "-l", str(root / "server.log"), "-o",
                 f"-h 127.0.0.1 -p {port} -k {root}", "-w", "start"])
        started = True

        def admin(sql, database="postgres"):
            return execute([str(binary / "psql"), "-X", "-qAt", "--no-password",
                            "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", str(port),
                            "-U", "postgres", "-d", database, "-f", "-"], input=sql)

        admin("CREATE ROLE notion_restore_owner LOGIN NOSUPERUSER NOCREATEDB "
              "NOCREATEROLE NOREPLICATION NOBYPASSRLS;")
        admin("CREATE DATABASE todo_restore_notion_lab OWNER notion_restore_owner;")
        admin("CREATE DATABASE todo_restore_notion_occupied OWNER notion_restore_owner;")
        admin("CREATE TABLE public.keep_existing (sentinel text); "
              "INSERT INTO public.keep_existing VALUES ('preserve-synthetic-existing');",
              "todo_restore_notion_occupied")
        passwords = root / "pgpass"
        passwords.write_text("", encoding="utf-8")
        passwords.chmod(0o600)

        def target_env(database):
            services = root / (database + ".service.conf")
            services.write_text(
                "[todo_recovery_target]\nhost=127.0.0.1\nport=" + str(port) +
                "\ndbname=" + database + "\nuser=notion_restore_owner\n",
                encoding="utf-8")
            services.chmod(0o600)
            return {**safe_env, "PGSERVICEFILE": str(services), "PGPASSFILE": str(passwords)}

        env = target_env("todo_restore_notion_lab")
        pg = Postgres(binary, env)

        # Key custody is simulated on this one runner and never claimed offhost.
        identity, public = key_material()
        identity_file = root / "synthetic-consumer-identity.pem"
        identity_file.write_bytes(identity)
        identity_file.chmod(0o600)
        del identity
        producer_env = hosted_env(public, producer_sha=producer_sha)
        source = CountingClient(SyntheticNotionClient())
        external_store = FakeDraftTransport()
        instant = datetime.now(timezone.utc)
        produced = hosted.run(producer_env, external_store, client=source, now=instant)
        source_calls = source.calls
        assert source_calls > 0 and external_store.uploads == 1
        assert produced["database_restore_verified"] is False
        assert produced["ciphertext_authentication_verified"] is False

        # Drop the producer's source/configuration before a separate download/CLI process.
        del source
        del producer_env
        asset = external_store.list_assets(produced["release_id"])[0]
        downloaded = external_store.readback(asset, 70 * 1024 * 1024)
        digest = hashlib.sha256(downloaded).hexdigest()
        assert digest == produced["ciphertext_sha256"]
        transferred = root / "independently-downloaded.sealed"
        transferred.write_bytes(downloaded)
        transferred.chmod(0o600)
        consumer_env = {**env, "TODO_RECOVERY_IDENTITY_FILE": str(identity_file),
                        "PYTHONPATH": str(ROOT / "scripts")}
        restored = json.loads(execute(
            [sys.executable, str(ROOT / "scripts/todo_notion_restore.py"),
             "--source", str(transferred), "--expected-sha256", digest,
             "--expected-producer-sha", producer_sha, "--bin-dir", str(binary)],
            env=consumer_env))
        assert restored["state"] == "notion_restore_verified"
        assert restored["restore_executed"] is True and restored["pages_verified"] == 3
        assert restored["ciphertext_authentication_verified"] is True
        assert restored["target_major"] == 18

        # A fresh administrative connection independently reads all inert projection data.
        independently_observed = json.loads(admin("""
SELECT json_build_object(
 'major',current_setting('server_version_num')::integer / 10000,
 'snapshot_sha256',(SELECT encode(sha256(snapshot_bytes),'hex')
                   FROM todo_notion_restore.snapshot_meta),
 'data_source',(SELECT document FROM todo_notion_restore.source_schema),
 'pages',(SELECT json_agg(document ORDER BY page_id) FROM todo_notion_restore.pages),
 'relation_count',(SELECT count(*) FROM pg_class c JOIN pg_namespace n
                   ON n.oid=c.relnamespace WHERE n.nspname='todo_notion_restore'
                   AND c.relkind='r'));
""", "todo_restore_notion_lab"))
        expected = synthetic_snapshot(producer_sha=producer_sha)
        expected_pages = sorted(expected["content"]["pages"], key=lambda row: row["page"]["id"])
        assert independently_observed["major"] == 18
        assert independently_observed["relation_count"] == 3
        assert independently_observed["snapshot_sha256"] == restored["snapshot_sha256"]
        assert recovery.canonical(independently_observed["pages"]) == recovery.canonical(expected_pages)
        assert (recovery.canonical(independently_observed["data_source"]) ==
                recovery.canonical(expected["content"]["data_source"]))
        assert not restored["canonical_cutover"] and not restored["workers_started"]

        recovery_key = identity_file.read_bytes()
        replay = recovery.recover_envelope(pg, downloaded, recovery_key, digest, producer_sha)
        assert replay["state"] == "notion_restore_already_verified"
        assert replay["restore_executed"] is False
        replay_env = hosted_env(public, producer_sha=producer_sha)
        replay_env.pop("TODO_NOTION_READ_TOKEN")
        producer_replay = hosted.run(replay_env, external_store, client=NeverClient(), now=instant)
        assert producer_replay["capture_executed"] is False
        assert producer_replay["source_sha"] is None and external_store.uploads == 1

        rejected = []
        def must_block(label, action):
            try:
                action()
            except (recovery.NotionRestoreBlocked, SealedBlocked):
                rejected.append(label)
            else:
                raise AssertionError("negative control accepted: " + label)

        tampered = downloaded[:-1] + bytes([downloaded[-1] ^ 1])
        must_block("outer_ciphertext_digest",
                   lambda: recovery.recover_envelope(object(), tampered, recovery_key,
                                                       digest, producer_sha))
        must_block("aead_authentication",
                   lambda: recovery.recover_envelope(object(), tampered, recovery_key,
                                                       hashlib.sha256(tampered).hexdigest(),
                                                       producer_sha))
        wrong_key, _ = key_material()
        must_block("wrong_recovery_key",
                   lambda: recovery.recover_envelope(object(), downloaded, wrong_key,
                                                       digest, producer_sha))
        must_block("producer_attestation",
                   lambda: recovery.recover_envelope(object(), downloaded, recovery_key,
                                                       digest, "b" * 40 if producer_sha != "b" * 40
                                                       else "c" * 40))
        occupied = Postgres(binary, target_env("todo_restore_notion_occupied"))
        must_block("occupied_target",
                   lambda: recovery.recover_envelope(occupied, downloaded, recovery_key,
                                                       digest, producer_sha))
        assert admin("SELECT sentinel FROM public.keep_existing;",
                     "todo_restore_notion_occupied") == "preserve-synthetic-existing"

        # A changed restored document must be detected, never silently overwritten on replay.
        admin("""UPDATE todo_notion_restore.pages SET document=document || '{"lab_drift":true}'::jsonb
WHERE page_id=(SELECT min(page_id) FROM todo_notion_restore.pages);""", "todo_restore_notion_lab")
        must_block("restored_page_drift",
                   lambda: recovery.recover_envelope(pg, downloaded, recovery_key,
                                                       digest, producer_sha))
        assert admin("SELECT count(*) FROM todo_notion_restore.pages "
                     "WHERE document ? 'lab_drift';", "todo_restore_notion_lab") == "1"
        assert len(rejected) == 6

        receipt = {
            "state": "synthetic_notion_native_restore_verified",
            "producer_sha": producer_sha, "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "postgres_major": 18, "postgres_runtime": "native",
            "capture_seal_download_cli_unseal_restore": True,
            "independent_sql_full_projection_verified": True,
            "pages_restored": 3, "native_projection_relations": 3,
            "source_rest_requests_simulated": source_calls,
            "source_transport": "synthetic_paginated_notion_rest",
            "storage_transport": "in_memory_fake_release",
            "producer_replay_without_source_or_upload": True,
            "restore_replay_without_write": True,
            "negative_controls": rejected,
            "real_user_data_used": False, "external_storage_verified": False,
            "offhost_custody_verified": False, "scheduled_execution_verified": False,
            "historical_neon_data_recovered": False, "notion_workspace_restored": False,
            "canonical_cutover": False, "workers_started": False, "backup_homologated": False,
        }
        receipt_path = ROOT / "todo-notion-recovery-e2e-receipt.json"
        with receipt_path.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, sort_keys=True, indent=2)
            output.write("\n")
        receipt_path.chmod(0o644)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    finally:
        if started:
            subprocess.run(["gosu", "postgres", str(binary / "pg_ctl"), "-D", str(data),
                            "-m", "fast", "-w", "stop"], capture_output=True, text=True,
                           timeout=30, check=False, env=safe_env)
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())
