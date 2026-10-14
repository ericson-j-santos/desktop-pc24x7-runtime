"""Positive, negative, idempotency and privacy controls for Desktop DEV inventory."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/reqsys_dev_readonly_inventory_receipt.py"
spec = importlib.util.spec_from_file_location("dev_readonly_inventory_receipt", SCRIPT)
assert spec is not None and spec.loader is not None
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)
RUNTIME_SHA = "a" * 40
REQSYS_SHA = "b" * 40
GATEWAY = "c" * 64
API = "d" * 64
DB = "e" * 64
PROJECT = "wt-pc24x7-piloto"
CORRELATION = "reqsys-dev-inventory-123-1"


def environment(**changes):
    source = {"GITHUB_REPOSITORY": receipt.REPOSITORY,
              "GITHUB_SHA": RUNTIME_SHA,
              "REQSYS_INVENTORY_CORRELATION": CORRELATION}
    source.update(changes)
    return source


def fixture(build_sha=REQSYS_SHA, *, compose=True):
    ids = {"nginx": GATEWAY, "api": API, "db": DB}
    def container(service):
        labels = {"com.docker.compose.project": PROJECT,
                  "com.docker.compose.service": service}
        if compose:
            labels.update({"com.docker.compose.project.config_files": r"C:\private\repo\compose.yml",
                           "com.docker.compose.project.working_dir": r"C:\private\repo"})
        return {"Id": ids[service], "Image": "sha256:" + ids[service],
                "Config": {"Labels": labels},
                "State": {"Running": True, "Health": {"Status": "healthy"}}}
    observed = {
        "status": "observed", "host": receipt.HOST, "source_sha": RUNTIME_SHA,
        "project": PROJECT, "gateway": {"service": "nginx", "container_id": GATEWAY},
        "api": {"service": "api", "container_id": API},
        "database_container": {"container_id": DB},
        "database_data_mounts": [{"type": "volume", "persistent": True, "writable": True}],
        "configured_database": {"dialect": "postgresql", "role": "private_role",
                                "database": "private_database"},
        "data_metadata": {"read_only_transaction": True, "counts_exact": True,
                          "table_counts": {"secret_table": 900}},
        "build_info": {"build_sha": build_sha},
        "gateway_api_route": {"verified": True},
        "container_inventory": [{"id": API, "project": PROJECT, "service": "api"}],
        "private_credential": "sensitive-marker-password",
    }
    calls = []
    def inspect(docker, identifier):
        calls.append((docker, identifier))
        service = next(s for s, i in ids.items() if i == identifier)
        return container(service)
    def validate_dev(item, project, service):
        assert item["Config"]["Labels"]["com.docker.compose.project"] == project
        assert item["Config"]["Labels"]["com.docker.compose.service"] == service
    p = SimpleNamespace(collect=lambda: observed,
                        inspected=inspect, validate_dev=validate_dev,
                        labels=lambda item: item["Config"]["Labels"],
                        health=lambda item: {"running": item["State"]["Running"],
                                             "health": item["State"]["Health"]["Status"]},
                        shutil=SimpleNamespace(which=lambda _: "docker"))
    return p, observed, calls


def test_positive_read_only_inventory_is_sanitized_and_not_cutover_proof():
    probe, _, calls = fixture()
    result = receipt.execute(probe, environment(), REQSYS_SHA)
    assert result["status"] == "observed"
    assert result["reason_code"] == "runtime_sha_matches"
    assert result["api_sha_matches_reqsys"] is True
    assert result["image_identities_complete"] is True
    assert result["compose_identity_complete"] is True
    assert result["database_volume_persistent"] is True
    assert result["database_readonly_metadata_verified"] is True
    assert result["database_consistent_backup_verified"] is False
    assert result["isolated_restore_verified"] is False
    assert result["service_rollback_verified"] is False
    assert result["cutover_ready"] is False
    assert len(calls) == 3
    raw = json.dumps(result, sort_keys=True)
    for private in ("sensitive-marker-password", "private_role", "private_database",
                    "secret_table", "C:\\private", "900"):
        assert private not in raw
    assert result["read_only"] is True and result["runtime_mutated"] is False


def test_sha_drift_and_missing_compose_contract_fail_closed_without_false_green():
    probe, _, _ = fixture("f" * 40, compose=False)
    result = receipt.execute(probe, environment(), REQSYS_SHA)
    assert result["status"] == "observed"
    assert result["reason_code"] == "runtime_sha_drift"
    assert result["api_sha_matches_reqsys"] is False
    assert result["compose_identity_complete"] is False
    assert result["service_rollback_verified"] is False
    assert result["cutover_ready"] is False


@pytest.mark.parametrize("changes,expected_code", [
    ({"GITHUB_REPOSITORY": "untrusted/public"}, "source_identity_invalid"),
    ({"GITHUB_SHA": "invalid"}, "source_identity_invalid"),
    ({"REQSYS_INVENTORY_CORRELATION": "private/secret"}, "correlation_invalid"),
])
def test_untrusted_source_identity_is_blocked_before_any_probe(changes, expected_code):
    probe, observed, _ = fixture()
    def never_probe():
        pytest.fail("probe must not run")
    probe.collect = never_probe
    result = receipt.execute(probe, environment(**changes), REQSYS_SHA)
    assert result["status"] == "blocked" and result["reason_code"] == expected_code
    assert result["cutover_ready"] is False
    assert "private" not in json.dumps(result)


def test_untrusted_dialect_and_unexpected_exception_never_export_raw_private_data():
    probe, observed, _ = fixture()
    observed["configured_database"] = {"dialect": "mysql://password-sensitive"}
    bad = receipt.execute(probe, environment(), REQSYS_SHA)
    assert bad["reason_code"] == "database_dialect_invalid"
    def sensitive_exception():
        raise OSError("sensitive-marker-password at C:\\secret\\location")
    probe.collect = sensitive_exception
    failed = receipt.execute(probe, environment(), REQSYS_SHA)
    assert failed["reason_code"] == "inventory_probe_unavailable"
    assert "sensitive-marker-password" not in json.dumps(failed)


def test_replay_is_idempotent_and_receipt_survives_independent_readback(monkeypatch, tmp_path):
    probe, _, _ = fixture()
    monkeypatch.setattr(receipt, "load_probe", lambda: probe)
    monkeypatch.chdir(tmp_path)
    for key, value in environment().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("REQSYS_TARGET_SHA", REQSYS_SHA)
    assert receipt.main() == 0
    first = (tmp_path / receipt.RECEIPT).read_bytes()
    assert receipt.main() == 0
    assert (tmp_path / receipt.RECEIPT).read_bytes() == first
    result = json.loads(first)
    assert result["source_runtime_sha"] == RUNTIME_SHA
    assert result["expected_reqsys_sha"] == REQSYS_SHA
    assert result["correlation_id"] == CORRELATION


def test_physical_workflow_is_gate_bound_and_never_dispatches_cutover():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/reqsys-dev-readonly-inventory.yml").read_text(encoding="utf-8")
    assert "--require-runner-version-preflight" in workflow
    assert "SESSION_LAUNCH_OK" in workflow
    assert "--risk', '1'" in workflow
    assert "--expected-head', $env:GITHUB_SHA" in workflow
    assert "scripts/reqsys_dev_readonly_inventory_receipt.py" in workflow
    assert "github.event_name == 'workflow_dispatch'" not in workflow
    assert "docker compose up" not in workflow.lower()
    assert "--risk', '2'" not in workflow
    assert "rollback" not in workflow.split("- name: Read-only Docker,")[1].split("- name: Independently")[0].lower()


def test_gateway_risk1_receipt_stays_outside_monitored_git_state(tmp_path: Path) -> None:
    """Mirror the pinned Gateway git ls-files --others exclusion and artifact upload."""
    assert receipt.RECEIPT.as_posix() == (
        ".tmp/reqsys-dev-readonly-inventory/evidence.json"
    )
    repo = tmp_path / "isolated-repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-q"],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    evidence = repo / receipt.RECEIPT
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"observed"}\n', encoding="utf-8")
    unfiltered = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "--", "."],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    filtered = subprocess.run(
        [
            "git", "ls-files", "--others", "--exclude-standard", "--",
            ".", ":(exclude).tmp/**",
        ],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert receipt.RECEIPT.as_posix() in unfiltered
    assert filtered == []
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/reqsys-dev-readonly-inventory.yml").read_text(
                    encoding="utf-8"
                )
    assert r"'.tmp\reqsys-dev-readonly-inventory\evidence.json'" in workflow
    assert "/.tmp/reqsys-dev-readonly-inventory/evidence.json" in workflow
    assert "include-hidden-files: true" in workflow
    assert "if-no-files-found: error" in workflow
    assert "/artifacts/reqsys-dev-readonly-inventory/evidence.json" not in workflow
