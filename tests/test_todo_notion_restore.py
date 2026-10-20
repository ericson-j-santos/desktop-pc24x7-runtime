"""Unit controls; the separate native E2E proves actual PostgreSQL effects."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import todo_notion_restore as recovery
from pc24x7_todo_recovery import RecoveryBlocked, service
import pc24x7_todo_recovery as pg_contract
from todo_notion_sealed import encrypt_notion
from notion_snapshot_fixture import synthetic_snapshot, PAGE_ONE
from notion_backup_test_support import key_material

NAMES = [recovery.SCHEMA + suffix for suffix in (".pages", ".snapshot_meta", ".source_schema")]
IDENTITY = {"database": "todo_restore_unit", "major": 18, "superuser": False,
            "createdb": False, "createrole": False, "replication": False, "bypassrls": False}


def payload():
    snapshot = synthetic_snapshot()
    raw = recovery.canonical(snapshot)
    manifest = {"schema_version": 1, "correlation_id": "synthetic-notion-restore",
                "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                "producer_sha": snapshot["producer_sha"]}
    return recovery.canonical(manifest), raw, manifest, snapshot


class FakePG:
    def __init__(self, manifest, raw, snapshot, *, occupied=False):
        self.env = {}
        self.identity = dict(IDENTITY)
        self.version = 18
        self.names = list(NAMES) if occupied else []
        self.queries = []
        self.observed = {
            "meta_count": 1, "schema_count": 1, "manifest": copy.deepcopy(manifest),
            "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
            "data_source": copy.deepcopy(snapshot["content"]["data_source"]),
            "page_ids": sorted(row["page"]["id"] for row in snapshot["content"]["pages"]),
            "pages": sorted(copy.deepcopy(snapshot["content"]["pages"]),
                            key=lambda row: row["page"]["id"]),
        }

    def sql(self, alias, query):
        assert alias == recovery.ALIAS
        self.queries.append(query)
        if query == recovery.IDENTITY_SQL:
            return copy.deepcopy(self.identity)
        if query == recovery.OCCUPIED_SQL:
            return list(self.names)
        if query == recovery.READBACK_SQL:
            return copy.deepcopy(self.observed)
        raise AssertionError("unexpected SQL")

    def major(self, tool):
        assert tool == "psql"
        return self.version


@pytest.fixture
def service_guard(monkeypatch):
    monkeypatch.setattr(recovery, "service",
                        lambda alias, env, target: {"dbname": "todo_restore_unit"})


def test_transaction_then_independent_readback_and_readonly_replay(monkeypatch, service_guard):
    manifest_bytes, raw, manifest, snapshot = payload()
    pg = FakePG(manifest, raw, snapshot)
    writes = []
    def transaction(target, sql):
        assert target is pg
        writes.append(sql)
        target.names = list(NAMES)
    monkeypatch.setattr(recovery, "_psql_input", transaction)
    receipt = recovery.restore_snapshot(pg, manifest_bytes, raw)
    assert len(writes) == 1 and writes[0].startswith("BEGIN;") and writes[0].endswith("COMMIT;")
    assert "pg_advisory_xact_lock" in writes[0] and "NOTION_TARGET_NOT_EMPTY" in writes[0]
    assert receipt["database_restore_verified"] is True and receipt["pages_verified"] == 3
    assert receipt["notion_workspace_restored"] is False
    assert receipt["historical_neon_data_recovered"] is False
    assert receipt["source_accessed"] is False and receipt["workers_started"] is False
    replay = recovery.restore_snapshot(pg, manifest_bytes, raw)
    assert replay["state"] == "notion_restore_already_verified"
    assert replay["restore_executed"] is False and len(writes) == 1
    assert pg.queries.count(recovery.READBACK_SQL) == 2


@pytest.mark.parametrize("changed,value", [
    ("database", "operational"), ("major", 17), ("superuser", True),
    ("createdb", True), ("createrole", True), ("replication", True), ("bypassrls", True),
])
def test_target_identity_and_restricted_role_are_required(monkeypatch, service_guard, changed, value):
    manifest_bytes, raw, manifest, snapshot = payload()
    pg = FakePG(manifest, raw, snapshot)
    pg.identity[changed] = value
    monkeypatch.setattr(recovery, "_psql_input", lambda *a: pytest.fail("target must not be written"))
    with pytest.raises(recovery.NotionRestoreBlocked):
        recovery.restore_snapshot(pg, manifest_bytes, raw)
    assert recovery.OCCUPIED_SQL not in pg.queries


def test_postgres_client_major_must_also_match(service_guard):
    _, raw, manifest, snapshot = payload()
    pg = FakePG(manifest, raw, snapshot)
    pg.version = 17
    with pytest.raises(recovery.NotionRestoreBlocked, match="POSTGRES18_REQUIRED"):
        recovery.target_identity(pg)


def test_occupied_database_is_rejected_before_write(monkeypatch, service_guard):
    manifest_bytes, raw, manifest, snapshot = payload()
    pg = FakePG(manifest, raw, snapshot)
    pg.names = ["public.existing_application_table"]
    monkeypatch.setattr(recovery, "_psql_input", lambda *a: pytest.fail("must not touch occupied target"))
    with pytest.raises(recovery.NotionRestoreBlocked, match="TARGET_NOT_EMPTY"):
        recovery.restore_snapshot(pg, manifest_bytes, raw)


@pytest.mark.parametrize("kind", ["snapshot", "manifest", "schema", "pages", "page_ids", "objects", "metadata"])
def test_replay_drift_fails_without_writes(monkeypatch, service_guard, kind):
    manifest_bytes, raw, manifest, snapshot = payload()
    pg = FakePG(manifest, raw, snapshot, occupied=True)
    if kind == "snapshot":
        pg.observed["snapshot_sha256"] = "0" * 64
    elif kind == "manifest":
        pg.observed["manifest"]["correlation_id"] = "changed"
    elif kind == "schema":
        pg.observed["data_source"] = {"changed": True}
    elif kind == "pages":
        pg.observed["pages"].pop()
    elif kind == "page_ids":
        # Preserve documents and ordering while changing only persisted lookup keys.
        pg.observed["page_ids"] = ["drift-" + value for value in pg.observed["page_ids"]]
    elif kind == "objects":
        pg.names.append("public.unexpected")
    else:
        pg.observed["meta_count"] = 0
    monkeypatch.setattr(recovery, "_psql_input", lambda *a: pytest.fail("replay must be read-only"))
    with pytest.raises(recovery.NotionRestoreBlocked):
        recovery.restore_snapshot(pg, manifest_bytes, raw)


def test_untrusted_page_text_is_encoded_and_never_becomes_sql():
    text = "'); DROP SCHEMA public CASCADE; -- dados sintéticos \u00e7"
    snapshot = {"content": {"data_source": {"title": text},
                           "pages": [{"page": {"id": PAGE_ONE}, "body": text}]}}
    sql = recovery.build_restore_sql(b"snapshot", snapshot, {"correlation_id": text})
    assert text not in sql and "DROP SCHEMA" not in sql
    assert "convert_from(decode('" in sql
    assert sql.count("BEGIN;") == 1 and sql.count("COMMIT;") == 1


def test_restore_payload_uses_stdin_and_filters_environment(monkeypatch):
    captured = {}
    secret_payload = "private synthetic payload, never a command argument"
    pg = SimpleNamespace(
        env={"PATH": "/native/bin", "PGSERVICEFILE": "/protected/service",
             "PGPASSFILE": "/protected/pass", "TODO_NOTION_READ_TOKEN": "do-not-inherit",
             "GITHUB_TOKEN": "do-not-inherit", "PGHOST": "outside"},
        command=lambda *args: ["psql", *args[1:]])
    def execute(args, **kwargs):
        captured.update(args=args, **kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(recovery.subprocess, "run", execute)
    recovery._psql_input(pg, secret_payload)
    assert captured["input"] == secret_payload
    assert secret_payload not in " ".join(captured["args"])
    assert "TODO_NOTION_READ_TOKEN" not in captured["env"]
    assert "GITHUB_TOKEN" not in captured["env"] and "PGHOST" not in captured["env"]
    assert captured["capture_output"] is True and captured["timeout"] == 150


@pytest.mark.parametrize("failure", ["error", "timeout"])
def test_subprocess_failures_never_echo_payload_or_stderr(monkeypatch, failure):
    pg = SimpleNamespace(env={}, command=lambda *args: ["psql"])
    def execute(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("secret-command", 1, stderr="secret-stderr")
        return SimpleNamespace(returncode=1, stdout="private-data", stderr="secret-stderr")
    monkeypatch.setattr(recovery.subprocess, "run", execute)
    with pytest.raises(recovery.NotionRestoreBlocked) as err:
        recovery._psql_input(pg, "private-input")
    assert "secret" not in str(err.value) and "private" not in str(err.value)


@pytest.mark.parametrize("host,database", [
    ("example.org", "todo_restore_unit"), ("127.0.0.1", "production"),
    ("localhost", "todo_restore_unit"),
])
def test_actual_service_parser_blocks_nonisolated_routes(tmp_path, monkeypatch, host, database):
    # ACL behavior has its own platform tests; isolate the routing guard here.
    monkeypatch.setattr(pg_contract, "validate_password_file", lambda path: None)
    services, passwords = tmp_path / "service.conf", tmp_path / "pgpass"
    services.write_text("[todo_recovery_target]\nhost=" + host + "\nport=5432\ndbname=" +
                        database + "\nuser=todo_restore_reader\n", encoding="utf-8")
    passwords.write_text("", encoding="utf-8")
    passwords.chmod(0o600)
    with pytest.raises(RecoveryBlocked, match="ISOLATED_LOCAL_TARGET_REQUIRED"):
        service(recovery.ALIAS, {"PGSERVICEFILE": str(services), "PGPASSFILE": str(passwords)},
                target=True)


def test_external_digest_required_before_decrypt_or_database_access():
    class NeverPG:
        pass
    with pytest.raises(recovery.NotionRestoreBlocked, match="CIPHERTEXT_DIGEST_MISMATCH"):
        recovery.recover_envelope(NeverPG(), b"changed", b"not-a-key", "0" * 64, "a" * 40)


def test_decrypted_manifest_must_match_independent_producer_sha():
    manifest_bytes, raw, _, _ = payload()
    identity, public = key_material()
    cipher = encrypt_notion(manifest_bytes, raw, public)
    with pytest.raises(recovery.NotionRestoreBlocked, match="PRODUCER_ATTESTATION_MISMATCH"):
        recovery.recover_envelope(object(), cipher, identity, hashlib.sha256(cipher).hexdigest(),
                                  "b" * 40)
