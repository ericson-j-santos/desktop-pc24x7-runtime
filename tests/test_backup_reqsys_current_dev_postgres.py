import importlib.util
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("backup_current_pg", SCRIPTS / "backup_reqsys_current_dev_postgres.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def test_toc_preserves_all_table_data_and_sequences_without_execution():
    toc = b"; Archive created\n1; 1259 100 TABLE public items reqsys_app\n2; 0 100 TABLE DATA public items reqsys_app\n3; 1259 101 SEQUENCE public items_id_seq reqsys_app\n4; 0 0 SEQUENCE SET public items_id_seq reqsys_app\n"
    assert backup.validate_toc(toc) == ["items"]


@pytest.mark.parametrize("entry", [
    "1; 1 1 FUNCTION public arbitrary() reqsys_app",
    "1; 1 1 TABLE public items another_owner",
    "1; 1 1 TABLE private items reqsys_app",
    "1; 1 1 EXTENSION - unsafe",
    "1; 1 1 DATABASE - other reqsys_app",
])
def test_unreviewed_archive_objects_are_rejected(entry):
    with pytest.raises(backup.BackupFailure):
        backup.validate_toc((entry + "\n2; 0 1 TABLE DATA public items reqsys_app\n").encode())


def test_backup_destination_always_fixed_to_localappdata():
    assert backup.HEADER == b"REQSYS-PG-DPAPI-V1\0"
    assert backup.MAX_BYTES == 32 * 1024 * 1024
    assert backup.PROJECT == "wt-pc24x7-piloto"


def test_dump_errors_do_not_expose_dump_or_driver_error_text(monkeypatch):
    class Process:
        returncode = 1
        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"PGDMPplaceholder-contents")
            self.stderr = io.BytesIO(b"placeholder-password-data")
        def wait(self, timeout=None): return 1
        def kill(self): pass
    monkeypatch.setattr(backup.subprocess, "Popen", lambda *args, **kwargs: Process())
    with pytest.raises(backup.BackupFailure, match="archive_command_failed") as caught:
        backup.capture(["docker", "exec", "fixed", "pg_dump"])
    assert "placeholder" not in str(caught.value)


def test_capture_rejects_archive_exceeding_memory_budget(monkeypatch):
    class Process:
        returncode = 0
        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"x" * 100)
            self.stderr = io.BytesIO()
        def wait(self, timeout=None): return 0
        def kill(self): pass
    monkeypatch.setattr(backup, "MAX_BYTES", 32)
    monkeypatch.setattr(backup.subprocess, "Popen", lambda *args, **kwargs: Process())
    with pytest.raises(backup.BackupFailure, match="archive_size_limit"):
        backup.capture(["fixed"])



def test_postgres16_public_schema_owner_is_allowed():
    toc = b"1; 2615 2200 SCHEMA - public pg_database_owner\n2; 0 100 TABLE DATA public items reqsys_app\n"
    assert backup.validate_toc(toc) == ["items"]


@pytest.mark.skipif(backup.os.name != "nt", reason="native Windows DPAPI and ACL")
def test_native_current_user_dpapi_roundtrip_and_protected_owner_acl(tmp_path):
    payload = b"PGDMP-ci-placeholder-private-data"
    protected = backup.protect(payload)
    assert protected.startswith(backup.HEADER)
    assert payload not in protected
    assert backup.unprotect(protected) == payload
    folder = tmp_path / "private"
    folder.mkdir()
    sid = backup.owner_sid()
    backup.private_acl(folder, sid)
    backup.assert_private_acl(folder, sid)
    path = folder / "test.dpapi"
    path.write_bytes(protected)
    backup.private_acl(path, sid)
    backup.assert_private_acl(path, sid)
    assert backup.unprotect(path.read_bytes()) == payload
