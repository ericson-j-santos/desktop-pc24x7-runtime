"""Bounded negative tests; nothing touches a host or a PostgreSQL database."""
import copy
import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import reqsys_native_release_admission as gate

S = "a" * 40
R = "b" * 40
ID = "41698530586"


def qualification():
    mount = lambda alias, size, avail, candidate: {
        "alias": alias, "present": True, "filesystem": "ext4" if alias == "root" else "9p",
        "size_gib_floor": size, "available_gib_floor": avail, "backup_capacity_candidate": candidate
    }
    return {
        "contract": "native-wsl-pg-qualification-v1", "host_alias": "authorized-primary",
        "source_sha": S, "rules_sha": R, "run_id": ID,
        "correlation_id": "dedicated-runner-" + ID + "-1", "run_attempt": 1,
        "runner_version": "2.338.2", "status": "measured", "linux_started": True,
        "default_distro_only": True, "init_system": "systemd",
        "systemd_state": "degraded", "wsl_conf_systemd_enabled": True,
        "systemd_verified": True,
        "mounts": [mount("root", 1006, 919, False),
                   mount("windows-volume-1", 1861, 1401, True),
                   mount("windows-volume-2", 49, 7, False)],
        "postgresql": {"psql_present": True, "cluster_tool_present": True,
                       "unit": {"load_state": "loaded", "active_state": "active", "enable_state": "enabled"},
                       "listeners_5432": [{"family": "ipv4", "bind": "wildcard"}]},
        "storage_durability_verified": False, "restart_verified": False,
        "backup_destination_selected": False, "database_target_qualified": False,
        "ready_for_installation": False, "database_connected": False,
        "database_contents_read": False, "credentials_read": False,
        "configuration_changed": False, "packages_installed": False,
        "network_changed": False,
    }


def evaluate(x=None, **kwargs):
    return gate.evaluate(x if x is not None else qualification(),
                         kwargs.get("runtime_sha", S), kwargs.get("rules_sha", R),
                         kwargs.get("run_id", ID))


def test_realistic_physical_report_blocks_native_migration():
    result = evaluate()
    assert result["status"] == "BLOCKED_NATIVE_DEV_RELEASE"
    assert result["highest_priority"] == "systemd_degraded"
    for k in ("postgres_listener_not_isolated", "database_identity_not_qualified",
              "storage_durability_unverified", "backup_not_qualified",
              "restart_not_verified", "installation_not_qualified"):
        assert k in result["blockers"]
    assert result["deployment_performed"] is False
    assert result["external_readback_verified"] is False


def test_all_true_fabricated_json_cannot_authorize_deploy():
    fake = qualification()
    fake.update(systemd_state="running", storage_durability_verified=True,
                restart_verified=True, backup_destination_selected=True,
                database_target_qualified=True, ready_for_installation=True)
    fake["postgresql"]["listeners_5432"] = [{"family": "ipv4", "bind": "loopback"}]
    result = evaluate(fake)
    assert result["blockers"] == ["external_attestation_required", "native_publisher_missing"]
    assert result["deployment_authorized"] is False
    assert result["deployment_performed"] is False


@pytest.mark.parametrize("field,wrong", [
    ("host_alias", "other"), ("source_sha", "c" * 40),
    ("rules_sha", "c" * 40), ("run_id", "12"),
    ("run_attempt", 2), ("correlation_id", "wrong")])
def test_wrong_origin_rejected(field, wrong):
    report = qualification()
    report[field] = wrong
    with pytest.raises(gate.AdmissionBlocked):
        evaluate(report)


@pytest.mark.parametrize("field", [
    "database_connected", "database_contents_read", "credentials_read",
    "configuration_changed", "packages_installed", "network_changed"])
def test_sensitive_or_mutating_probe_rejected(field):
    report = qualification()
    report[field] = True
    with pytest.raises(gate.AdmissionBlocked):
        evaluate(report)


def test_bool_string_is_not_verification():
    report = qualification()
    report["ready_for_installation"] = "true"
    with pytest.raises(gate.AdmissionBlocked):
        evaluate(report)


def test_unexpected_file_schema_and_sha_rejected():
    report = qualification()
    report["url"] = "https://example.net"
    with pytest.raises(gate.AdmissionBlocked):
        evaluate(report)
    with pytest.raises(gate.AdmissionBlocked):
        evaluate(runtime_sha="main")


def test_replay_has_same_fingerprint_without_automatic_retry():
    first, second = evaluate(), evaluate(copy.deepcopy(qualification()))
    assert first == second
    assert len(first["fingerprint_sha256"]) == 64
    assert first["automatic_retry"] is False


def test_cli_blocks_and_produces_sanitized_evidence(tmp_path, capsys):
    data = tmp_path / "inventory.json"
    out = tmp_path / "out.json"
    data.write_text(json.dumps(qualification()), encoding="utf-8")
    rc = gate.main(["--qualification", str(data), "--runtime-sha", S,
                    "--rules-sha", R, "--run-id", ID, "--output", str(out)])
    assert rc == 3
    value = json.loads(out.read_text(encoding="utf-8"))
    assert "postgresql" not in value
    assert "mounts" not in value
    assert value["deployment_performed"] is False
    assert "NATIVE_REQSYS_DEV_RELEASE_BLOCKED" in capsys.readouterr().out


def test_invalid_input_no_output(tmp_path):
    data, out = tmp_path / "bad.json", tmp_path / "out.json"
    data.write_text("{not json", encoding="utf-8")
    rc = gate.main(["--qualification", str(data), "--runtime-sha", S,
                    "--rules-sha", R, "--run-id", ID, "--output", str(out)])
    assert rc == 2
    assert not out.exists()
