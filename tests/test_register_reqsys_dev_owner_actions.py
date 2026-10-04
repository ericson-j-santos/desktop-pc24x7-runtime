"""The prepare-only grant registry never edits owner policy until exact review."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import pytest

FILE = Path(__file__).resolve().parents[1] / "scripts/register_reqsys_dev_owner_actions.py"
SPEC = importlib.util.spec_from_file_location("reqsys_owner_registry", FILE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
SOURCE_SHA = "a" * 40
LAUNCHER_SHA = "b" * 64
DIGESTS = {"prepare": "d" * 64}
PYTHON = "C:/owned/python.exe"
NOW = datetime(2026, 10, 3, 13, 17, tzinfo=timezone.utc)

def config():
    return {
        "version": 1, "enabled": True,
        "owner_fingerprint": "PRIVATE-OWNER-FINGERPRINT",
        "development_mode": {
            "enabled": False, "reason": "preserve-this",
            "allowed_roots": ["PRIVATE-UNRELATED-ROOT"],
        },
        "actions": {
            "unrelated.local.action": {"private": "PRESERVE-ME"},
            "reqsys.selfhost.receiver.init.dev": {"private": "PRESERVE-RECEIVER"},
        },
        "other_private_setting": "DO-NOT-PRINT",
    }

def plan(value=None, now=NOW, source_sha=SOURCE_SHA, digests=DIGESTS):
    value = config() if value is None else value
    raw = m.canonical(value)
    return m.build_plan(value, raw, source_sha, digests, LAUNCHER_SHA, PYTHON, now)

def test_prepare_only_grant_preserves_every_unrelated_value():
    original = config()
    snapshot = copy.deepcopy(original)
    proposed, evidence = plan(original)
    assert original == snapshot
    assert proposed["development_mode"] == snapshot["development_mode"]
    assert proposed["actions"]["unrelated.local.action"] == snapshot["actions"]["unrelated.local.action"]
    for key in set(original) - {"actions"}:
        assert proposed[key] == original[key]
    assert set(proposed["actions"]) - set(original["actions"]) == set(m.ACTION_IDS.values())
    assert {item["scope"] for item in evidence["actions"]} == set(m.SCOPES.values())
    assert len(evidence["actions"]) == 1
    assert evidence["actions"][0]["action_id"] == "reqsys.selfhost.publisher.prepare.dev"
    assert proposed["actions"]["reqsys.selfhost.receiver.init.dev"] == snapshot["actions"]["reqsys.selfhost.receiver.init.dev"]
    assert set(m.SCRIPTS) == {"prepare"}
    assert evidence["read_only"] is True
    assert evidence["maximum_validity_seconds"] == 3600
    assert evidence["expires_at"] == "2026-10-03T14:00:00+00:00"

def test_public_plan_never_exposes_private_config():
    _, evidence = plan()
    serialized = json.dumps(evidence)
    for value in ("PRIVATE-OWNER-FINGERPRINT", "PRIVATE-UNRELATED-ROOT",
                  "PRESERVE-ME", "PRESERVE-RECEIVER", "DO-NOT-PRINT"):
        assert value not in serialized
    assert "owner_fingerprint" not in serialized
    assert "command" not in serialized

def test_review_digest_is_stable_and_hour_boundary_requires_new_review():
    _, initial = plan(now=NOW)
    _, same = plan(now=NOW + timedelta(minutes=1))
    _, later = plan(now=NOW + timedelta(hours=1))
    assert initial["plan_sha256"] == same["plan_sha256"]
    assert later["plan_sha256"] != initial["plan_sha256"]
    with pytest.raises(m.OperationError, match="reviewed_plan_changed"):
        m.authorize_apply(later, m.APPLY_CONFIRM, initial["plan_sha256"], False)

def test_apply_requires_both_exact_phrase_and_reviewed_digest():
    _, evidence = plan()
    with pytest.raises(m.OperationError, match="closed_apply_confirmation_required"):
        m.authorize_apply(evidence, "YES", evidence["plan_sha256"], False)
    with pytest.raises(m.OperationError, match="reviewed_plan_sha256_required"):
        m.authorize_apply(evidence, m.APPLY_CONFIRM, "", False)
    with pytest.raises(m.OperationError, match="reviewed_plan_changed"):
        m.authorize_apply(evidence, m.APPLY_CONFIRM, "0" * 64, False)
    m.authorize_apply(evidence, m.APPLY_CONFIRM, evidence["plan_sha256"], False)

def test_live_replay_keeps_expiry_and_never_extends_window():
    initial, first = plan()
    replay, evidence = plan(initial, now=NOW + timedelta(minutes=10))
    assert replay == initial
    assert evidence["operation"] == "replay"
    assert evidence["changes_required"] is False
    assert evidence["expires_at"] == first["expires_at"]

def test_renewal_requires_specific_confirmation_and_explicit_flag():
    initial, _ = plan()
    renewed, evidence = plan(initial, now=NOW + timedelta(hours=1))
    assert evidence["operation"] == "renew"
    assert renewed["development_mode"] == initial["development_mode"]
    with pytest.raises(m.OperationError, match="explicit_expired_renewal_required"):
        m.authorize_apply(evidence, m.RENEW_CONFIRM, evidence["plan_sha256"], False)
    with pytest.raises(m.OperationError, match="closed_apply_confirmation_required"):
        m.authorize_apply(evidence, m.APPLY_CONFIRM, evidence["plan_sha256"], True)
    m.authorize_apply(evidence, m.RENEW_CONFIRM, evidence["plan_sha256"], True)

@pytest.mark.parametrize("change", ("unknown", "command", "scope", "window", "extra"))
def test_existing_collision_is_never_overwritten(change):
    initial, _ = plan()
    grant = initial["actions"][m.ACTION_IDS["prepare"]]
    if change == "unknown":
        grant.pop("grant_contract")
    elif change == "command":
        grant["command"] = ["python", "arbitrary.py"]
    elif change == "scope":
        grant["scope"] = "repo://reqsys/environment/prod"
    elif change == "window":
        grant["expires_at"] = "2026-10-03T15:00:00+00:00"
    else:
        grant["unknown"] = "do-not-overwrite"
    with pytest.raises(m.OperationError):
        plan(initial)

def test_active_other_source_cannot_be_rebound():
    initial, _ = plan()
    with pytest.raises(m.OperationError, match="active_grants_bound_to_other_source"):
        plan(initial, source_sha="e" * 40)

@pytest.mark.parametrize("source_sha", ("", "A" * 40, "a" * 39, "../escape"))
def test_bad_source_sha_cannot_construct_grants(source_sha):
    with pytest.raises(m.OperationError, match="invalid_source_sha"):
        plan(source_sha=source_sha)

def test_wrong_owner_disabled_gateway_and_broad_mode_fail_closed():
    current = config()
    with pytest.raises(m.OperationError, match="configuration_owner_mismatch"):
        m.validate_config(current, "different-owner")
    current["enabled"] = False
    with pytest.raises(m.OperationError, match="existing_owner_gateway_must_be_enabled"):
        m.validate_config(current, current["owner_fingerprint"])
    current["enabled"] = True
    current["development_mode"]["enabled"] = True
    with pytest.raises(m.OperationError, match="broad_development_mode_must_remain_disabled"):
        m.validate_config(current, current["owner_fingerprint"])

def test_source_bundle_checks_only_publisher_and_launcher_hashes(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(m, "source_root", lambda _: tmp_path)
    monkeypatch.setattr(m, "validate_repository", lambda root, sha: calls.append(("repo", root, sha)))
    monkeypatch.setattr(m, "validate_scripts", lambda root, values: calls.append(("scripts", root, values)))
    assert m.validate_source_bundle(SOURCE_SHA, DIGESTS, LAUNCHER_SHA) == tmp_path
    assert calls[1][2] == {
        m.LAUNCHER: LAUNCHER_SHA,
        m.SCRIPTS["prepare"]: DIGESTS["prepare"],
    }

def prepare_main(monkeypatch, tmp_path):
    original = config()
    monkeypatch.setattr(m, "require_owner", lambda: None)
    monkeypatch.setattr(m, "validate_source_bundle", lambda *_: tmp_path)
    monkeypatch.setattr(m, "python_executable", lambda: PYTHON)
    monkeypatch.setattr(m, "WindowsPrivateFiles", lambda: object())
    monkeypatch.setattr(m, "read_config", lambda *_: (m.canonical(original), original))
    return [
        "--source-sha", SOURCE_SHA,
        "--prepare-script-sha256", DIGESTS["prepare"],
        "--launcher-script-sha256", LAUNCHER_SHA,
    ]

def test_default_main_does_not_write(monkeypatch, tmp_path, capsys):
    argv = prepare_main(monkeypatch, tmp_path)
    def forbidden(*_):
        raise AssertionError("default must never write")
    monkeypatch.setattr(m, "atomic_apply", forbidden)
    assert m.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["read_only"] is True

def test_apply_without_confirmation_never_writes(monkeypatch, tmp_path, capsys):
    argv = prepare_main(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(m, "atomic_apply", lambda *_: calls.append("write"))
    assert m.main(argv + ["--apply"]) == 2
    assert not calls
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

@pytest.mark.parametrize("extra", ("--config", "--action-id", "--scope", "--command", "--ttl", "--source-root", "--recipient-script-sha256"))
def test_cli_never_accepts_arbitrary_route(extra):
    with pytest.raises(SystemExit):
        m.build_parser().parse_args([
            "--source-sha", SOURCE_SHA,
            "--prepare-script-sha256", DIGESTS["prepare"],
            "--launcher-script-sha256", LAUNCHER_SHA, extra, "arbitrary",
        ])

class FakePrivate:
    def check_readable(self, _path):
        return None
    def check(self, _path):
        return None
    def secure(self, _path):
        return None

@pytest.mark.parametrize("failure", ("secure", "replace"))
def test_permission_failures_leave_existing_bytes_intact(monkeypatch, tmp_path, failure):
    path = tmp_path / m.CONFIG_NAME
    original = m.canonical(config())
    path.write_bytes(original)
    proposed, _ = plan()
    private = FakePrivate()
    def denied(*_):
        raise PermissionError("simulated")
    if failure == "secure":
        monkeypatch.setattr(private, "secure", denied)
    else:
        monkeypatch.setattr(m.os, "replace", denied)
    with pytest.raises(PermissionError):
        m.atomic_apply(path, private, original, proposed)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]

def test_concurrent_policy_change_is_preserved(monkeypatch, tmp_path):
    path = tmp_path / m.CONFIG_NAME
    original = m.canonical(config())
    changed = original + b"\n"
    path.write_bytes(changed)
    proposed, _ = plan()
    with pytest.raises(m.OperationError, match="configuration_changed_during_review"):
        m.atomic_apply(path, FakePrivate(), original, proposed)
    assert path.read_bytes() == changed
    assert list(tmp_path.iterdir()) == [path]

@pytest.mark.skipif(os.name != "nt", reason="actual protected Windows file DACL")
def test_real_windows_atomic_grant_file_acl(tmp_path):
    path = tmp_path / m.CONFIG_NAME
    original = m.canonical(config())
    path.write_bytes(original)
    private = m.WindowsPrivateFiles()
    private.secure(path)
    proposed, _ = plan()
    m.atomic_apply(path, private, original, proposed)
    private.check(path)
    assert json.loads(path.read_text("ascii")) == proposed
    assert list(tmp_path.iterdir()) == [path]


def readable_acl_fixture():
    private = object.__new__(m.WindowsPrivateFiles)
    private.sid = "S-1-5-21-100"
    aliases = {
        private.sid: private.sid,
        "BA": "S-1-5-32-544", "SY": "S-1-5-18",
        "BU": "S-1-5-32-545", "AU": "S-1-5-11", "WD": "S-1-1-0",
    }
    private._canonical_sid = lambda value: aliases.get(value, value)
    return private

@pytest.mark.parametrize("flags", ("", "P", "AI", "PAI"))
def test_admin_owner_legacy_acl_is_readable_only_with_closed_principals(flags):
    private = readable_acl_fixture()
    sddl = (
        f"O:BAD:{flags}(A;ID;FA;;;{private.sid})"
        "(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
    )
    assert private._validate_readable_sddl(sddl) == "administrators"

@pytest.mark.parametrize("principal", ("BU", "AU", "WD", "S-1-5-21-999"))
def test_public_or_unknown_ace_principal_is_rejected(principal):
    private = readable_acl_fixture()
    sddl = (
        f"O:BAD:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        f"(A;;FR;;;{principal})"
    )
    with pytest.raises(m.OperationError, match="configuration_acl_unknown_principal"):
        private._validate_readable_sddl(sddl)

@pytest.mark.parametrize("owner", ("SY", "BU", "S-1-5-21-999"))
def test_file_owner_is_closed_to_current_user_or_admins(owner):
    private = readable_acl_fixture()
    sddl = f"O:{owner}D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FA;;;BA)"
    with pytest.raises(m.OperationError, match="configuration_acl_owner_not_current_user_or_administrators"):
        private._validate_readable_sddl(sddl)

def test_trusted_admin_owner_still_needs_current_user_ace():
    private = readable_acl_fixture()
    with pytest.raises(m.OperationError, match="configuration_acl_current_user_access_missing"):
        private._validate_readable_sddl("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")

def set_actual_test_security(private, path, sddl, admin_owner=False):
    descriptor = m.ctypes.c_void_p()
    assert private.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, m.ctypes.byref(descriptor), None
    )
    try:
        if not private.adv.SetFileSecurityW(str(path), 0x80000005, descriptor):
            error = m.ctypes.get_last_error()
            if admin_owner and error in (1307, 1314):
                pytest.skip("CI token cannot assign Administrators file owner")
            pytest.fail("Windows test security descriptor assignment failed")
    finally:
        private.kernel.LocalFree(descriptor)

@pytest.mark.skipif(os.name != "nt", reason="actual legacy Windows Administrators owner")
def test_real_windows_admin_owned_legacy_plan_is_read_only(monkeypatch, tmp_path):
    path = tmp_path / m.CONFIG_NAME
    current = config()
    original = m.canonical(current)
    path.write_bytes(original)
    private = m.WindowsPrivateFiles()
    set_actual_test_security(
        private, path,
        f"O:BAD:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FA;;;BA)",
        admin_owner=True,
    )
    monkeypatch.setattr(m, "owner_fingerprint", lambda: current["owner_fingerprint"])
    private.check_readable(path)
    assert private.readable_owner_category == "administrators"
    raw, parsed = m.read_config(path, private)
    assert raw == original
    assert parsed == current
    proposed, evidence = m.build_plan(
        parsed, raw, SOURCE_SHA, DIGESTS, LAUNCHER_SHA, PYTHON, NOW
    )
    assert evidence["read_only"] is True
    assert len(evidence["actions"]) == 1
    assert proposed["development_mode"] == current["development_mode"]
    assert proposed["actions"]["reqsys.selfhost.receiver.init.dev"] == current["actions"]["reqsys.selfhost.receiver.init.dev"]
    assert parsed == current
    assert path.read_bytes() == original
    private.check_readable(path)
    assert private.readable_owner_category == "administrators"

@pytest.mark.skipif(os.name != "nt", reason="actual Windows untrusted Users DACL")
def test_real_windows_users_acl_rejected_before_config_bytes(monkeypatch, tmp_path):
    path = tmp_path / m.CONFIG_NAME
    path.write_bytes(b"PRIVATE-CONFIG-SENTINEL")
    private = m.WindowsPrivateFiles()
    set_actual_test_security(
        private, path,
        f"O:{private.sid}D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
    )
    reads = []
    def forbidden_read(_path):
        reads.append(True)
        raise AssertionError("untrusted DACL must fail before bytes")
    monkeypatch.setattr(m.Path, "read_bytes", forbidden_read)
    with pytest.raises(m.OperationError, match="configuration_acl_unknown_principal"):
        m.read_config(path, private)
    assert reads == []
