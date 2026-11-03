#!/usr/bin/env python3
"""Evaluate native ReqSys DEV readiness, without making mutations or approving a deploy."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from scripts import native_wsl_pg_qualification as qualification
except ImportError:
    import native_wsl_pg_qualification as qualification

CONTRACT = "reqsys-native-dev-admission-v1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
MAX_BYTES = 16384
STEPS = {
    "systemd_degraded": "investigar unidades systemd com falha apenas em leitura",
    "postgres_unit_not_active": "qualificar unidade PostgreSQL sem reiniciar servicos",
    "postgres_listener_not_isolated": "comprovar isolamento da porta 5432",
    "postgres_tools_absent": "validar ferramentas PostgreSQL sem instalar pacotes",
    "database_identity_not_qualified": "identificar base ReqSys pelo plano de controle",
    "storage_durability_unverified": "provar persistencia de dados e armazenamento",
    "backup_not_qualified": "selecionar backup independente e testar restauracao",
    "restart_not_verified": "validar retomada de servico e rollback em ambiente isolado",
    "installation_not_qualified": "comprovar publicador DEV nativo instalado",
    "external_attestation_required": "atestar evidencias via API oficial e SHA",
    "native_publisher_missing": "implementar publicador imutavel com backup e rollback",
}


class AdmissionBlocked(ValueError):
    pass


def checked_bool(value):
    if type(value) is not bool:
        raise AdmissionBlocked("invalid_boolean")
    return value


def evaluate(report: dict, runtime_sha: str, rules_sha: str, run_id: str) -> dict:
    if not isinstance(report, dict):
        raise AdmissionBlocked("invalid_report")
    if any(not isinstance(x, str) or SHA.fullmatch(x) is None for x in (runtime_sha, rules_sha)):
        raise AdmissionBlocked("invalid_sha")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise AdmissionBlocked("invalid_run_id")
    try:
        qualification.validate(report)
    except (qualification.QualificationBlocked, KeyError, TypeError, ValueError):
        raise AdmissionBlocked("invalid_qualification_contract") from None
    if (report.get("source_sha") != runtime_sha or
        report.get("rules_sha") != rules_sha or
        report.get("run_id") != run_id or
        report.get("host_alias") != "authorized-primary" or
        type(report.get("run_attempt")) is not int or report["run_attempt"] != 1 or
        report.get("correlation_id") != "dedicated-runner-" + run_id + "-1"):
        raise AdmissionBlocked("unverified_origin_binding")
    for key in ("linux_started", "default_distro_only", "systemd_verified",
                "wsl_conf_systemd_enabled", "storage_durability_verified",
                "restart_verified", "backup_destination_selected",
                "database_target_qualified", "ready_for_installation",
                "database_connected", "database_contents_read", "credentials_read",
                "configuration_changed", "packages_installed", "network_changed"):
        checked_bool(report.get(key))
    if any(report[key] for key in (
        "database_connected", "database_contents_read", "credentials_read",
        "configuration_changed", "packages_installed", "network_changed")):
        raise AdmissionBlocked("unexpected_mutation_or_sensitive_access")
    pg = report.get("postgresql")
    if not isinstance(pg, dict) or set(pg) != {
        "psql_present", "cluster_tool_present", "unit", "listeners_5432"
    }:
        raise AdmissionBlocked("invalid_postgres_contract")
    checked_bool(pg["psql_present"])
    checked_bool(pg["cluster_tool_present"])
    unit, listeners = pg["unit"], pg["listeners_5432"]
    if (not isinstance(unit, dict) or
        set(unit) != {"load_state", "active_state", "enable_state"} or
        not isinstance(listeners, list) or
        any(not isinstance(x, dict) or set(x) != {"family", "bind"} or
            x["family"] not in ("ipv4", "ipv6") or
            x["bind"] not in ("loopback", "wildcard", "other") for x in listeners)):
        raise AdmissionBlocked("invalid_postgres_contract")
    missing = set()
    if (not report["linux_started"] or not report["default_distro_only"] or
        not report["systemd_verified"] or not report["wsl_conf_systemd_enabled"] or
        report.get("init_system") != "systemd" or
        report.get("systemd_state") != "running"):
        missing.add("systemd_degraded")
    if unit != {"load_state": "loaded", "active_state": "active", "enable_state": "enabled"}:
        missing.add("postgres_unit_not_active")
    if not listeners or any(row["bind"] != "loopback" for row in listeners):
        missing.add("postgres_listener_not_isolated")
    if not pg["psql_present"] or not pg["cluster_tool_present"]:
        missing.add("postgres_tools_absent")
    if not report["database_target_qualified"]:
        missing.add("database_identity_not_qualified")
    if not report["storage_durability_verified"]:
        missing.add("storage_durability_unverified")
    if (not report["backup_destination_selected"] or
        not any(row.get("backup_capacity_candidate") is True for row in report["mounts"])):
        missing.add("backup_not_qualified")
    if not report["restart_verified"]:
        missing.add("restart_not_verified")
    if not report["ready_for_installation"]:
        missing.add("installation_not_qualified")
    # Originating JSON is never authenticated evidence, even when all flags are True.
    missing.update(("external_attestation_required", "native_publisher_missing"))
    blockers = [item for item in STEPS if item in missing]
    priority = blockers[0]
    fingerprint = hashlib.sha256(json.dumps({
        "contract": CONTRACT, "environment": "dev",
        "runtime_sha": runtime_sha, "blockers": blockers,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "contract": CONTRACT, "environment": "dev",
        "status": "BLOCKED_NATIVE_DEV_RELEASE",
        "runtime_source_sha": runtime_sha, "qualification_run_id": run_id,
        "blockers": blockers, "highest_priority": priority,
        "next_action": STEPS[priority], "fingerprint_sha256": fingerprint,
        "external_readback_verified": False, "backup_restored_independently": False,
        "rollback_verified_independently": False, "native_publisher_installed": False,
        "deployment_authorized": False, "deployment_performed": False,
        "production_touched": False, "automatic_retry": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify DEV WSL posture; no deployment")
    parser.add_argument("--runtime-sha", required=True)
    parser.add_argument("--rules-sha", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    root = Path.cwd()
    artifacts = root / "artifacts"
    input_dir = artifacts / "native-pg-inventory"
    output_dir = artifacts / "reqsys-native-dev-admission"
    evidence_file = input_dir / "evidence.json"
    output_file = output_dir / "decision.json"
    try:
        # Nunca aceitar input/output externo ao worktree governado nem reparse point.
        for item in (root, artifacts, input_dir, evidence_file, output_dir, output_file):
            if item.is_symlink():
                raise AdmissionBlocked("reparse_path_rejected")
        if not artifacts.is_dir() or not input_dir.is_dir():
            raise AdmissionBlocked("fixed_artifact_root_missing")
        if not evidence_file.is_file() or evidence_file.stat().st_size > MAX_BYTES:
            raise AdmissionBlocked("source_missing_or_large")
        report = json.loads(evidence_file.read_text(encoding="utf-8"))
        result = evaluate(report, args.runtime_sha, args.rules_sha, args.run_id)
        serialized = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if output_file.exists():
            if not output_file.is_file() or output_file.read_text(encoding="utf-8") != serialized:
                raise AdmissionBlocked("existing_receipt_conflict")
        else:
            output_dir.mkdir(exist_ok=True)
            if output_dir.is_symlink():
                raise AdmissionBlocked("reparse_path_rejected")
            # Exclusivo e sem overwrite; replay idempotente não cria nova versão.
            with output_file.open("x", encoding="utf-8") as stream:
                stream.write(serialized)
    except (AdmissionBlocked, OSError, TypeError, ValueError):
        print("NATIVE_REQSYS_DEV_ADMISSION_BLOCKED", file=sys.stderr)
        return 2
    print("NATIVE_REQSYS_DEV_RELEASE_BLOCKED")
    return 3

if __name__ == "__main__":
    raise SystemExit(main())
