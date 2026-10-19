"""Restore a verified Notion snapshot into an isolated native PostgreSQL 18 database.

This is an inert recovery projection, never a new TODO queue or an operational
upsert. No source API, consumers, history replay, or canonical cutover is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from pc24x7_todo_recovery import Postgres, RecoveryBlocked, service
from pc24x7_todo_sealed import SealedBlocked, read_file, strict_json
from todo_notion_sealed import decrypt_notion, validate_notion_payload
from todo_notion_snapshot import NotionBlocked, validate_snapshot

ALIAS = "todo_recovery_target"
SCHEMA = "todo_notion_restore"
MAX_SNAPSHOT = 64 * 1024 * 1024
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")


class NotionRestoreBlocked(RuntimeError):
    """A fixed error code only; no source document or connection details."""


def require(ok, reason):
    if not ok:
        raise NotionRestoreBlocked(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


IDENTITY_SQL = """SELECT json_build_object(
 'database',current_database(),
 'major',current_setting('server_version_num')::integer / 10000,
 'superuser',r.rolsuper,'createdb',r.rolcreatedb,'createrole',r.rolcreaterole,
 'replication',r.rolreplication,'bypassrls',r.rolbypassrls)
 FROM pg_roles r WHERE r.rolname=current_user"""

OCCUPIED_SQL = """SELECT coalesce(json_agg(n.nspname || '.' || c.relname
 ORDER BY n.nspname,c.relname),'[]'::json)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
 AND c.relkind IN ('r','p','v','m','S','f')"""

READBACK_SQL = """SELECT json_build_object(
 'meta_count',(SELECT count(*) FROM todo_notion_restore.snapshot_meta),
 'schema_count',(SELECT count(*) FROM todo_notion_restore.source_schema),
 'manifest',(SELECT manifest FROM todo_notion_restore.snapshot_meta WHERE singleton),
 'snapshot_sha256',(SELECT encode(sha256(snapshot_bytes),'hex')
                    FROM todo_notion_restore.snapshot_meta WHERE singleton),
 'data_source',(SELECT document FROM todo_notion_restore.source_schema WHERE singleton),
 'pages',coalesce((SELECT json_agg(document ORDER BY page_id)
                  FROM todo_notion_restore.pages),'[]'::json))"""


def target_identity(pg):
    target = service(ALIAS, pg.env, target=True)
    identity = pg.sql(ALIAS, IDENTITY_SQL)
    require(isinstance(identity, dict) and identity.get("database") == target["dbname"],
            "NOTION_TARGET_IDENTITY_MISMATCH")
    require(identity.get("major") == 18 and pg.major("psql") == 18,
            "NOTION_NATIVE_POSTGRES18_REQUIRED")
    require(all(identity.get(key) is False for key in
                ("superuser", "createdb", "createrole", "replication", "bypassrls")),
            "NOTION_RESTRICTED_RESTORE_ROLE_REQUIRED")
    return identity


def _psql_input(pg, sql):
    """Private payload travels on stdin, never in argv, env, stdout or stderr logs."""
    allowed = ("PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "PGSERVICEFILE", "PGPASSFILE")
    env = {key: pg.env[key] for key in allowed if key in pg.env}
    env.update(PGCONNECT_TIMEOUT="10", PGAPPNAME="todo-notion-inert-restore",
               PGOPTIONS="-c statement_timeout=120000 -c lock_timeout=10000")
    try:
        result = subprocess.run(
            pg.command("psql", "-X", "-qAt", "--no-password", "-v", "ON_ERROR_STOP=1",
                       "-d", "service=" + ALIAS, "-f", "-"),
            input=sql, text=True, encoding="utf-8", capture_output=True,
            timeout=150, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise NotionRestoreBlocked("NOTION_RESTORE_EXECUTION_UNAVAILABLE") from None
    require(result.returncode == 0, "NOTION_RESTORE_TRANSACTION_FAILED")


def _hex_json(value):
    return "convert_from(decode('" + canonical(value).hex() + "','hex'),'UTF8')::jsonb"


def build_restore_sql(snapshot_bytes, snapshot, manifest):
    """Only fixed SQL identifiers and hexadecimal data literals are generated."""
    require(0 < len(snapshot_bytes) <= MAX_SNAPSHOT, "NOTION_SNAPSHOT_SIZE_INVALID")
    document = snapshot["content"]
    inserts = []
    for item in document["pages"]:
        identifier = item["page"]["id"]
        require(isinstance(identifier, str) and
                re.fullmatch(r"[0-9a-fA-F-]{32,36}", identifier) is not None,
                "NOTION_RESTORE_PAGE_ID_INVALID")
        # The ID is validated and also encoded instead of interpolated into SQL.
        id_sql = "convert_from(decode('" + identifier.encode().hex() + "','hex'),'UTF8')"
        inserts.append("INSERT INTO todo_notion_restore.pages VALUES (" +
                       id_sql + "," + _hex_json(item) + ");")
    return "\n".join([
        "BEGIN;",
        "SET LOCAL timezone='UTC';",
        "SELECT pg_advisory_xact_lock(746631, hashtext(current_database()));",
        """DO $notion_restore_gate$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
    AND c.relkind IN ('r','p','v','m','S','f'))
 OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='todo_notion_restore')
 THEN RAISE EXCEPTION 'NOTION_TARGET_NOT_EMPTY'; END IF;
 END $notion_restore_gate$;""",
        "CREATE SCHEMA todo_notion_restore;",
        """CREATE TABLE todo_notion_restore.snapshot_meta(
 singleton boolean PRIMARY KEY CHECK(singleton),
 snapshot_bytes bytea NOT NULL, manifest jsonb NOT NULL);""",
        """CREATE TABLE todo_notion_restore.source_schema(
 singleton boolean PRIMARY KEY CHECK(singleton), document jsonb NOT NULL);""",
        """CREATE TABLE todo_notion_restore.pages(
 page_id text PRIMARY KEY, document jsonb NOT NULL);""",
        "INSERT INTO todo_notion_restore.snapshot_meta VALUES (true,decode('" +
        snapshot_bytes.hex() + "','hex')," + _hex_json(manifest) + ");",
        "INSERT INTO todo_notion_restore.source_schema VALUES (true," +
        _hex_json(document["data_source"]) + ");",
        *inserts,
        "COMMIT;"
    ])


def verify_projection(pg, snapshot_bytes, snapshot, manifest):
    expected_names = [
        SCHEMA + ".pages", SCHEMA + ".snapshot_meta", SCHEMA + ".source_schema"
    ]
    require(pg.sql(ALIAS, OCCUPIED_SQL) == expected_names,
            "NOTION_RESTORED_OBJECT_SET_CHANGED")
    observed = pg.sql(ALIAS, READBACK_SQL)
    require(isinstance(observed, dict) and observed.get("meta_count") == 1 and
            observed.get("schema_count") == 1, "NOTION_RESTORE_RECEIPT_SET_INVALID")
    require(observed.get("snapshot_sha256") == hashlib.sha256(snapshot_bytes).hexdigest(),
            "NOTION_RESTORED_SNAPSHOT_DRIFT")
    require(canonical(observed.get("manifest")) == canonical(manifest),
            "NOTION_RESTORED_MANIFEST_DRIFT")
    require(canonical(observed.get("data_source")) ==
            canonical(snapshot["content"]["data_source"]), "NOTION_RESTORED_SCHEMA_DRIFT")
    expected = sorted(snapshot["content"]["pages"], key=lambda row: row["page"]["id"])
    require(canonical(observed.get("pages")) == canonical(expected),
            "NOTION_RESTORED_PAGE_DRIFT")
    return len(expected)


def restore_snapshot(pg, manifest_bytes, snapshot_bytes):
    manifest = validate_notion_payload(manifest_bytes, snapshot_bytes)
    snapshot = strict_json(snapshot_bytes)
    validate_snapshot(snapshot)
    identity = target_identity(pg)
    before = pg.sql(ALIAS, OCCUPIED_SQL)
    expected_names = [SCHEMA + ".pages", SCHEMA + ".snapshot_meta", SCHEMA + ".source_schema"]
    if before:
        require(before == expected_names, "NOTION_TARGET_NOT_EMPTY")
        rows = verify_projection(pg, snapshot_bytes, snapshot, manifest)
        executed = False
    else:
        _psql_input(pg, build_restore_sql(snapshot_bytes, snapshot, manifest))
        # New process/read-only connection, checking the actual stored projection.
        rows = verify_projection(pg, snapshot_bytes, snapshot, manifest)
        executed = True
    return {
        "state": "notion_restore_verified" if executed else "notion_restore_already_verified",
        "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "producer_sha": manifest["producer_sha"],
        "correlation_id": manifest["correlation_id"],
        "target_database": identity["database"],
        "target_major": identity["major"],
        "pages_verified": rows,
        "restore_executed": executed,
        "database_restore_verified": True,
        "source_accessed": False,
        "canonical_cutover": False,
        "workers_started": False,
        "historical_neon_data_recovered": False,
        "notion_workspace_restored": False
    }


def recover_envelope(pg, envelope, identity_pem, expected_sha256, expected_producer_sha):
    require(isinstance(expected_sha256, str) and SHA64.fullmatch(expected_sha256),
            "NOTION_EXPECTED_CIPHERTEXT_SHA_REQUIRED")
    require(isinstance(expected_producer_sha, str) and SHA40.fullmatch(expected_producer_sha),
            "NOTION_EXPECTED_PRODUCER_SHA_REQUIRED")
    require(hashlib.sha256(envelope).hexdigest() == expected_sha256,
            "NOTION_CIPHERTEXT_DIGEST_MISMATCH")
    manifest_bytes, snapshot_bytes = decrypt_notion(envelope, identity_pem)
    manifest = validate_notion_payload(manifest_bytes, snapshot_bytes)
    require(manifest["producer_sha"] == expected_producer_sha,
            "NOTION_PRODUCER_ATTESTATION_MISMATCH")
    result = restore_snapshot(pg, manifest_bytes, snapshot_bytes)
    return {**result, "ciphertext_sha256": expected_sha256,
            "ciphertext_authentication_verified": True,
            "offhost_custody_verified": False,
            "external_download_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-producer-sha", required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        location = os.environ.get("TODO_RECOVERY_IDENTITY_FILE", "")
        require(bool(location), "NOTION_PROTECTED_IDENTITY_REFERENCE_REQUIRED")
        identity = read_file(Path(location), 16384, private=True)
        envelope = read_file(args.source, MAX_SNAPSHOT + 128 * 1024 + 16384)
        result = recover_envelope(Postgres(args.bin_dir), envelope, identity,
                                  args.expected_sha256, args.expected_producer_sha)
    except (NotionRestoreBlocked, RecoveryBlocked, SealedBlocked, NotionBlocked) as error:
        result = {"state": "blocked", "reason": str(error), "canonical_cutover": False}
    except Exception:
        result = {"state": "blocked", "reason": "NOTION_RESTORE_UNEXPECTED_FAILURE",
                  "canonical_cutover": False}
    print(json.dumps(result, sort_keys=True))
    return 2 if result["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
