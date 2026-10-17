#!/usr/bin/env python3
"""Read-only verification of a private TODO catalog ZIP against public hash-only evidence.

The ZIP stays private. This tool neither fetches, prints, uploads, nor dispatches
TODO records. It does not verify a PostgreSQL backup or authorize any cutover.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import stat
import zipfile

MAX_ARCHIVE = 10 * 1024 * 1024
MAX_MEMBER = 2 * 1024 * 1024
EXPECTED = frozenset({"todo-catalog.json", "local-validation.json", "manifest.json", "README.md"})
FIELDS = frozenset({"todo_id", "url", "title", "project", "status", "e2e_status", "priority", "idempotency_key", "correlation_id", "external_id", "evidence_url", "updated_at", "created_at"})
STATES = frozenset({"PENDENTE", "EM ANDAMENTO", "BLOQUEADO", "CONCLUÍDO", "CANCELADO"})


class InvalidCatalog(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise InvalidCatalog(code)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def parse_json(raw: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            require(key not in value, "DUPLICATE_JSON_KEY")
            value[key] = item
        return value

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidCatalog("NONFINITE_JSON")))
    except (UnicodeError, json.JSONDecodeError):
        raise InvalidCatalog("INVALID_JSON") from None


def verify(archive: Path, checkpoint: dict) -> dict:
    """Validate bytes, selected source identities and an in-memory reconstruction.

    Never expose record values in receipts or exceptions.
    """
    require(type(checkpoint) is dict and checkpoint.get("contract") == "todo-catalog-github-checkpoint-v1", "CHECKPOINT_INVALID")
    require(checkpoint.get("raw_uploaded_to_public_git") is False, "PUBLIC_RAW_DATA_FORBIDDEN")
    require(checkpoint.get("cutover_ready") is False and checkpoint.get("postgresql_backup_verified") is False, "CHECKPOINT_STATE_UNSAFE")
    require(type(checkpoint.get("record_count")) is int and checkpoint["record_count"] > 0, "CHECKPOINT_COUNT_INVALID")
    require(type(checkpoint.get("source_state_counts")) is dict, "CHECKPOINT_STATES_INVALID")
    require(type(checkpoint.get("archive_size_bytes")) is int, "CHECKPOINT_SIZE_INVALID")
    require(type(checkpoint.get("archive_sha256")) is str and len(checkpoint["archive_sha256"]) == 64, "CHECKPOINT_DIGEST_INVALID")

    require(not archive.is_symlink() and archive.is_file(), "ARCHIVE_NOT_REGULAR")
    require(archive.stat().st_size <= MAX_ARCHIVE, "ARCHIVE_TOO_LARGE")
    raw = archive.read_bytes()
    require(len(raw) == checkpoint["archive_size_bytes"], "ARCHIVE_SIZE_MISMATCH")
    require(digest(raw) == checkpoint["archive_sha256"], "ARCHIVE_HASH_MISMATCH")
    try:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            require(len(names) == len(EXPECTED) and set(names) == EXPECTED, "ARCHIVE_MEMBERS_INVALID")
            require(all(i.file_size <= MAX_MEMBER and not i.is_dir() for i in infos), "MEMBER_SIZE_INVALID")
            require(all(not stat.S_ISLNK(i.external_attr >> 16) for i in infos), "ARCHIVE_SYMLINK_FORBIDDEN")
            blobs = {n: z.read(n) for n in EXPECTED}
    except InvalidCatalog:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError):
        raise InvalidCatalog("ARCHIVE_STRUCTURE_INVALID") from None
    manifest = parse_json(blobs["manifest.json"])
    require(isinstance(manifest, dict) and manifest.get("contract") == "file-integrity-manifest-v1", "MANIFEST_INVALID")
    require(manifest.get("cutover_ready") is False, "MANIFEST_CUTOVER_INVALID")
    require(manifest.get("snapshot_id") == checkpoint.get("snapshot_id"), "SNAPSHOT_ID_MISMATCH")
    file_info = manifest.get("files")
    require(isinstance(file_info, dict) and set(file_info) == EXPECTED - {"manifest.json"}, "MANIFEST_FILES_INVALID")
    for n, meta in file_info.items():
        require(isinstance(meta, dict) and type(meta.get("bytes")) is int and type(meta.get("sha256")) is str, "MANIFEST_MEMBER_INVALID")
        require(meta["bytes"] == len(blobs[n]) and meta["sha256"] == digest(blobs[n]), "MANIFEST_MEMBER_MISMATCH")
    require(digest(blobs["todo-catalog.json"]) == checkpoint.get("catalog_sha256"), "CATALOG_DIGEST_MISMATCH")
    cat = parse_json(blobs["todo-catalog.json"])
    require(isinstance(cat, dict) and cat.get("contract") == "todo-global-catalog-snapshot-v1", "CATALOG_CONTRACT_INVALID")
    for name in ("cutover_ready", "dispatch_authorized", "contains_postgresql_data", "contains_page_bodies", "contains_attachments"):
        require(cat.get(name) is False, "CATALOG_UNSAFE_FLAGS")
    require(cat.get("active_partition_only") is True, "CATALOG_SCOPE_INVALID")
    require(cat.get("snapshot_id") == checkpoint.get("snapshot_id"), "SNAPSHOT_ID_MISMATCH")
    fields = cat.get("fields")
    require(isinstance(fields, list) and len(fields) == len(FIELDS) and all(type(field) is str for field in fields) and set(fields) == FIELDS, "CATALOG_FIELDS_INVALID")
    records = cat.get("records")
    require(isinstance(records, list) and len(records) == checkpoint["record_count"] and cat.get("record_count") == len(records), "CATALOG_COUNT_MISMATCH")
    require(all(type(x) is dict and set(x) == FIELDS for x in records), "CATALOG_RECORD_INVALID")
    require(all(type(x["todo_id"]) is int and x["todo_id"] > 0 and type(x["url"]) is str and x["url"] and type(x["idempotency_key"]) is str and x["idempotency_key"] and type(x["status"]) is str and x["status"] in STATES for x in records), "CATALOG_IDENTITIES_INVALID")
    require(len({x["todo_id"] for x in records}) == len(records), "DUPLICATE_TODO_ID")
    require(len({x["url"] for x in records}) == len(records), "DUPLICATE_URL")
    require(len({x["idempotency_key"] for x in records}) == len(records), "DUPLICATE_IDEMPOTENCY_KEY")
    states = dict(sorted(Counter(x["status"] for x in records).items()))
    require(states == checkpoint["source_state_counts"], "STATE_COUNT_MISMATCH")
    validation = parse_json(blobs["local-validation.json"])
    require(isinstance(validation, dict) and validation.get("dispatch_performed") is not True and validation.get("workers_started") is False and validation.get("cutover_ready") is False, "VALIDATION_UNSAFE")
    require(validation.get("source_record_count") == len(records) and validation.get("json_sha256") == checkpoint["catalog_sha256"], "VALIDATION_MISMATCH")

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE catalog (todo_id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE, payload BLOB NOT NULL)")
        ordered = sorted(records, key=lambda x: x["todo_id"])
        rows = [(r["todo_id"], r["url"], r["idempotency_key"], json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()) for r in ordered]
        conn.executemany("INSERT INTO catalog VALUES(?,?,?,?)", rows)
        restored = conn.execute("SELECT payload FROM catalog ORDER BY todo_id").fetchall()
        require([x[0] for x in restored] == [x[3] for x in rows], "RESTORE_IN_MEMORY_MISMATCH")
        before = conn.total_changes
        conn.executemany("INSERT OR IGNORE INTO catalog VALUES(?,?,?,?)", rows)
        require(conn.total_changes == before, "REPLAY_WRITTEN_ROWS")
    finally:
        conn.close()
    return {"state": "catalog_verified", "snapshot_id": checkpoint["snapshot_id"],
            "record_count": len(records), "archive_sha256": digest(raw), "replay_written_rows": 0,
            "source_state_counts": states, "postgresql_backup_verified": False,
            "cutover_ready": False, "raw_uploaded_to_public_git": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="Private ZIP path (never upload to GitHub public repos)")
    parser.add_argument("--checkpoint", type=Path, required=True, help="Sanitized versioned checkpoint")
    args = parser.parse_args()
    try:
        require(args.checkpoint.is_file() and not args.checkpoint.is_symlink(), "CHECKPOINT_NOT_REGULAR")
        require(args.checkpoint.stat().st_size <= 16384, "CHECKPOINT_TOO_LARGE")
        result = verify(args.archive, parse_json(args.checkpoint.read_bytes()))
    except (InvalidCatalog, OSError, ValueError) as exc:
        print(json.dumps({"state": "blocked", "reason": str(exc) if isinstance(exc, InvalidCatalog) else "INVALID_INPUT", "cutover_ready": False}))
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
