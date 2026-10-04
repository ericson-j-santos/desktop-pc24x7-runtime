"""Reviewed one-file ACL repair; no authority comes from its own confirmation flags."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import pytest

FILE = Path(__file__).resolve().parents[1] / "scripts/apply_owner_risk3_file_acl_repair.py"
SPEC = importlib.util.spec_from_file_location("owner_acl_repair_apply", FILE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

def private_fixture():
    private = object.__new__(m.r.WindowsPrivateFiles)
    private.sid = "S-1-5-21-100"
    aliases = {"BA": "S-1-5-32-544", "SY": "S-1-5-18", "BU": "S-1-5-32-545"}
    private._canonical_sid = lambda value: aliases.get(value, value)
    return private

def original(private):
    return f"O:BAD:P(A;ID;FA;;;{private.sid})(A;ID;FA;;;SY)(A;;FR;;;BU)"

class Backup:
    def __init__(self):
        self.saved = []
    def preserve(self, value):
        self.saved.append(value)

def test_confirmation_or_review_mismatch_never_backs_up_or_mutates(monkeypatch, tmp_path):
    private = private_fixture()
    before = original(private)
    digest = m.plan.build_plan(before, private)["plan_sha256"]
    backup = Backup()
    writes = []
    monkeypatch.setattr(m, "set_security", lambda *a: writes.append(a))
    for confirm, reviewed in (("YES", digest), (m.CONFIRM, ""), (m.CONFIRM, "0" * 64)):
        with pytest.raises(m.r.OperationError):
            m.apply_reviewed(tmp_path / m.r.CONFIG_NAME, private, before, confirm, reviewed, backup)
    assert backup.saved == []
    assert writes == []

def test_acl_change_before_repair_prevents_mutation(monkeypatch, tmp_path):
    private = private_fixture()
    before = original(private)
    digest = m.plan.build_plan(before, private)["plan_sha256"]
    observed = iter((before, before + "(A;;FR;;;BA)"))
    monkeypatch.setattr(m.plan, "read_security", lambda *_: next(observed))
    writes = []
    monkeypatch.setattr(m, "set_security", lambda *a: writes.append(a))
    backup = Backup()
    with pytest.raises(m.r.OperationError, match="changed_before_repair"):
        m.apply_reviewed(tmp_path / m.r.CONFIG_NAME, private, before, m.CONFIRM, digest, backup)
    assert backup.saved == [before]
    assert not writes

def test_reviewed_repair_orders_backup_then_cas_then_dacl_only(monkeypatch, tmp_path):
    private = private_fixture()
    before = original(private)
    after = f"O:BAD:P(A;;FA;;;{private.sid})(A;;FA;;;SY)"
    digest = m.plan.build_plan(before, private)["plan_sha256"]
    observed = iter((before, before, after))
    monkeypatch.setattr(m.plan, "read_security", lambda *_: next(observed))
    events = []
    backup = Backup()
    def save(value):
        backup.saved.append(value)
        events.append("backup")
    backup.preserve = save
    def write(path, win, descriptor, flags):
        events.append("write_dacl")
        assert flags == 0x80000004
        assert descriptor.startswith("D:P")
        assert "O:" not in descriptor
    monkeypatch.setattr(m, "set_security", write)
    result = m.apply_reviewed(tmp_path / m.r.CONFIG_NAME, private, before, m.CONFIRM, digest, backup)
    assert events == ["backup", "write_dacl"]
    assert result["owner_preserved"] is True
    assert result["configuration_bytes_changed"] is False
    assert result["grants_changed"] is False

def test_postcondition_rejects_extra_reader_or_owner_change():
    private = private_fixture()
    before = original(private)
    with pytest.raises(m.r.OperationError):
        m.verify_target(before, f"O:BAD:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FR;;;BU)", private)
    with pytest.raises(m.r.OperationError, match="owner_changed"):
        m.verify_target(before, f"O:{private.sid}D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)", private)

def test_no_arbitrary_path_or_shell_input():
    for argv in (["--path", "arbitrary"], ["--command", "arbitrary"], ["--elevate"]):
        with pytest.raises(SystemExit):
            m.main(argv)

@pytest.mark.skipif(os.name != "nt", reason="actual DPAPI and protected Windows DACL")
def test_native_windows_repair_preserves_content_and_dpapi_backup(monkeypatch, tmp_path):
    target = tmp_path / m.r.CONFIG_NAME
    content = b"PRIVATE-CONFIG-CONTENT"
    target.write_bytes(content)
    private = m.r.WindowsPrivateFiles()
    # Synthetic test file, never the real local owner configuration.
    m.set_security(
        target, private,
        f"O:{private.sid}D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FR;;;BU)",
        0x80000005,
    )
    before = m.plan.read_security(target, private)
    digest = m.plan.build_plan(before, private)["plan_sha256"]
    backup_root = tmp_path / "PrivateAclRepair"
    backup_file = backup_root / "owner-risk3-exceptions.original.dacl.dpapi"
    monkeypatch.setattr(m.r, "CONFIG_ROOT", tmp_path)
    monkeypatch.setattr(m, "BACKUP_ROOT", backup_root)
    monkeypatch.setattr(m, "BACKUP_FILE", backup_file)
    result = m.apply_reviewed(target, private, before, m.CONFIRM, digest, m.PrivateBackup(private))
    assert result["status"] == "repaired"
    assert target.read_bytes() == content
    assert m.dpapi(backup_file.read_bytes(), decrypt=True) == m.PREFIX + before.encode("utf-8")
    m.PrivateBackup(private).check(backup_root)
    m.PrivateBackup(private).check(backup_file)
    m.verify_target(before, m.plan.read_security(target, private), private)
