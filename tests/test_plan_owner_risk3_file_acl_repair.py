"""Read-only ACL repair proposal contracts; no target configuration byte reads."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import pytest

FILE = Path(__file__).resolve().parents[1] / "scripts/plan_owner_risk3_file_acl_repair.py"
SPEC = importlib.util.spec_from_file_location("acl_repair_plan", FILE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

def private_fixture():
    private = object.__new__(m.registry.WindowsPrivateFiles)
    private.sid = "S-1-5-21-100"
    aliases = {"BA": "S-1-5-32-544", "SY": "S-1-5-18", "BU": "S-1-5-32-545"}
    private._canonical_sid = lambda value: aliases.get(value, value)
    return private

def trusted_source(private, flags=""):
    return f"O:BAD:P(A;{flags};FA;;;{private.sid})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

@pytest.mark.parametrize("flags", ("", "ID"))
def test_plan_accepts_effective_current_sid_and_preserves_owner(flags):
    private = private_fixture()
    result = m.build_plan(trusted_source(private, flags), private)
    assert result["read_only"] is True
    assert result["approval_required"] is True
    assert result["apply_available"] is False
    assert result["proposed_acl"]["owner_preserved"] is True
    assert result["configuration_bytes_read"] is False
    assert result["grants_changed"] is False
    assert result["before_acl"]["principal_categories"]["users"]["allow"] == 1
    assert "S-1-" not in json.dumps(result)
    assert "O:BA" not in json.dumps(result)

def test_non_effective_or_untrusted_owner_is_blocked():
    private = private_fixture()
    with pytest.raises(m.registry.OperationError, match="effective_access_missing"):
        m.build_plan(trusted_source(private, "IO"), private)
    with pytest.raises(m.registry.OperationError, match="owner_not_current_user_or_administrators"):
        m.build_plan(trusted_source(private).replace("O:BA", "O:SY"), private)

def test_plan_digest_changes_with_existing_descriptor():
    private = private_fixture()
    first = m.build_plan(trusted_source(private), private)
    second = m.build_plan(trusted_source(private).replace(";;;BU", ";;;S-1-5-21-999"), private)
    assert first["plan_sha256"] != second["plan_sha256"]

def test_default_cli_never_reads_target_bytes_or_writes(monkeypatch, capsys):
    private = private_fixture()
    # Build fixture before replacing the class.
    monkeypatch.setattr(m.registry, "require_owner", lambda: None)
    monkeypatch.setattr(m.registry, "WindowsPrivateFiles", lambda: private)
    monkeypatch.setattr(m, "read_security", lambda *_: trusted_source(private))
    def forbidden(*_):
        raise AssertionError("target file bytes must not be accessed")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    assert m.main([]) == 0
    assert json.loads(capsys.readouterr().out)["read_only"] is True

def test_apply_and_arbitrary_paths_are_not_available():
    for argv in (["--apply"], ["--path", "arbitrary"], ["--command", "arbitrary"]):
        with pytest.raises(SystemExit):
            m.main(argv)

@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor plan")
def test_actual_windows_plan_preserves_file_content_and_dacl(tmp_path):
    path = tmp_path / m.registry.CONFIG_NAME
    original = b"PRIVATE-CONFIG-SENTINEL"
    path.write_bytes(original)
    private = m.registry.WindowsPrivateFiles()
    private.secure(path)
    before = m.read_security(path, private)
    result = m.build_plan(before, private)
    assert result["read_only"] is True
    assert m.read_security(path, private) == before
    assert path.read_bytes() == original
