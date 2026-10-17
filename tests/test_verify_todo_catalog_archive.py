"""No private backup bytes are committed to CI; all fixtures are synthetic."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("todo_catalog_verifier", ROOT / "scripts/verify_todo_catalog_archive.py")
verify_mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_mod)


def j(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def synthetic(tmp_path, mutate=None, *, extra=None, duplicate_json=False):
    records = [{field: "synthetic" for field in verify_mod.FIELDS} for _ in range(2)]
    records[0].update(todo_id=1, url="https://example.invalid/1", idempotency_key="key1", status="BLOQUEADO")
    records[1].update(todo_id=2, url="https://example.invalid/2", idempotency_key="key2", status="EM ANDAMENTO")
    cat = {"contract": "todo-global-catalog-snapshot-v1", "cutover_ready": False,
           "dispatch_authorized": False, "contains_postgresql_data": False,
           "contains_page_bodies": False, "contains_attachments": False,
           "active_partition_only": True, "snapshot_id": "synthetic-20261017",
           "fields": sorted(verify_mod.FIELDS), "records": records, "record_count": 2}
    val = {"cutover_ready": False, "workers_started": False, "source_record_count": 2}
    manifest = {"contract": "file-integrity-manifest-v1", "cutover_ready": False,
                "snapshot_id": "synthetic-20261017", "files": {}}
    if mutate:
        mutate(cat, val, manifest)
    raw = j(cat)
    val["json_sha256"] = verify_mod.digest(raw)
    members = {"todo-catalog.json": raw, "local-validation.json": j(val), "README.md": b"Synthetic test data only."}
    if duplicate_json:
        members["todo-catalog.json"] = raw[:-1] + b',"record_count":2}'
    for name, content in members.items():
        manifest["files"][name] = {"bytes": len(content), "sha256": verify_mod.digest(content)}
    if extra:
        members.update(extra)
    members["manifest.json"] = j(manifest)
    filename = tmp_path / "catalog.zip"
    with zipfile.ZipFile(filename, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    checkpoint = {"contract": "todo-catalog-github-checkpoint-v1", "archive_sha256": verify_mod.digest(filename.read_bytes()),
                  "archive_size_bytes": filename.stat().st_size, "record_count": 2,
                  "catalog_sha256": verify_mod.digest(members["todo-catalog.json"]),
                  "snapshot_id": "synthetic-20261017", "source_state_counts": {"BLOQUEADO": 1, "EM ANDAMENTO": 1},
                  "raw_uploaded_to_public_git": False, "cutover_ready": False, "postgresql_backup_verified": False}
    return filename, checkpoint


def blocks(tmp_path, change=None, *, reason, **kwargs):
    arc, ck = synthetic(tmp_path, change, **kwargs)
    with pytest.raises(verify_mod.InvalidCatalog, match=reason):
        verify_mod.verify(arc, ck)


def test_real_synthetic_roundtrip_and_replay_no_writes(tmp_path):
    archive, checkpoint = synthetic(tmp_path)
    result = verify_mod.verify(archive, checkpoint)
    assert result["state"] == "catalog_verified"
    assert result["record_count"] == 2
    assert result["replay_written_rows"] == 0
    assert result["cutover_ready"] is False
    assert verify_mod.verify(archive, checkpoint) == result
    assert set(x.name for x in tmp_path.iterdir()) == {"catalog.zip"}


def test_archive_digest_mismatch_blocks_before_open(tmp_path):
    archive, ck = synthetic(tmp_path)
    ck["archive_sha256"] = "a" * 64
    with pytest.raises(verify_mod.InvalidCatalog, match="ARCHIVE_HASH_MISMATCH"):
        verify_mod.verify(archive, ck)


def test_file_size_mismatch(tmp_path):
    archive, ck = synthetic(tmp_path)
    ck["archive_size_bytes"] += 1
    with pytest.raises(verify_mod.InvalidCatalog, match="ARCHIVE_SIZE_MISMATCH"):
        verify_mod.verify(archive, ck)


def test_duplicate_id_rejected_even_if_zip_hash_and_manifest_recomputed(tmp_path):
    blocks(tmp_path, lambda c,v,m: c["records"][1].update(todo_id=1), reason="DUPLICATE_TODO_ID")


def test_duplicate_identity_key_rejected(tmp_path):
    blocks(tmp_path, lambda c,v,m: c["records"][1].update(idempotency_key="key1"), reason="DUPLICATE_IDEMPOTENCY_KEY")


def test_duplicate_url_rejected(tmp_path):
    blocks(tmp_path, lambda c,v,m: c["records"][1].update(url="https://example.invalid/1"), reason="DUPLICATE_URL")


def test_dispatch_flag_rejected(tmp_path):
    blocks(tmp_path, lambda c,v,m: c.update(dispatch_authorized=True), reason="CATALOG_UNSAFE_FLAGS")


def test_wrong_status_count_rejected(tmp_path):
    blocks(tmp_path, lambda c,v,m: c["records"][1].update(status="BLOQUEADO"), reason="STATE_COUNT_MISMATCH")


def test_count_mismatch_rejected(tmp_path):
    blocks(tmp_path, lambda c,v,m: c.update(record_count=1), reason="CATALOG_COUNT_MISMATCH")


def test_invalid_status_type_rejected_with_stable_reason(tmp_path):
    blocks(tmp_path, lambda c,v,m: c["records"][1].update(status={"bad": 1}), reason="CATALOG_IDENTITIES_INVALID")


def test_zip_path_traversal_rejected(tmp_path):
    blocks(tmp_path, reason="ARCHIVE_MEMBERS_INVALID", extra={"../exfiltrate.json": b"bad"})


def test_zip_symlink_rejected(tmp_path):
    archive, ck = synthetic(tmp_path)
    with zipfile.ZipFile(archive) as z:
        all_files = {info.filename: z.read(info.filename) for info in z.infolist()}
    with zipfile.ZipFile(archive, "w") as z:
        for name, raw in all_files.items():
            i = zipfile.ZipInfo(name)
            if name == "README.md":
                i.create_system = 3
                i.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(i, raw)
    ck["archive_sha256"] = verify_mod.digest(archive.read_bytes())
    ck["archive_size_bytes"] = archive.stat().st_size
    with pytest.raises(verify_mod.InvalidCatalog, match="ARCHIVE_SYMLINK_FORBIDDEN"):
        verify_mod.verify(archive, ck)


def test_duplicate_json_property_rejected(tmp_path):
    blocks(tmp_path, reason="DUPLICATE_JSON_KEY", duplicate_json=True)


def test_rejects_invalid_checkpoint_states(tmp_path):
    archive, ck = synthetic(tmp_path)
    ck["raw_uploaded_to_public_git"] = True
    with pytest.raises(verify_mod.InvalidCatalog, match="PUBLIC_RAW_DATA_FORBIDDEN"):
        verify_mod.verify(archive, ck)


def test_checkpoints_contain_no_external_storage_ids_or_raw_records():
    checkpoint = json.loads((ROOT / "evidence/todo-global/catalog-20261017-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["raw_uploaded_to_public_git"] is False
    assert checkpoint["data_storage"] == "private_drive_only"
    serialized = json.dumps(checkpoint)
    for needle in ("drive.google.com", "drive_file_id", "drive_file_url", "records", "idempotency_key", "external_id", "@"):
        assert needle not in serialized


def test_no_external_calls_or_writes_in_validator():
    source = (ROOT / "scripts/verify_todo_catalog_archive.py").read_text(encoding="utf-8")
    assert 'sqlite3.connect(":memory:")' in source
    for marker in ("requests.", "urllib.request", "subprocess.", "shell=True", "ALTER TABLE", "DROP TABLE", "dispatch(", ".write_bytes("):
        assert marker not in source


def test_windows_default_encoding_does_not_control_source_reads():
    test_source = Path(__file__).read_text(encoding="utf-8")
    prelude = test_source.split("def test_windows_default_encoding_does_not_control_source_reads():")[0]
    assert ".read_text()" not in prelude
    assert prelude.count('read_text(encoding="utf-8")') >= 2
