#!/usr/bin/env python3
"""Sanitized, read-only ReqSys DEV inventory over the existing Desktop probe.

Never writes to the application, starts containers, exports rows, or deploys.
A probe failure produces a stable blocked receipt, not a success.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

HOST = "DESKTOP-PDQK954"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
PROJECTS = frozenset({"wt-pc24x7-piloto", "wt-pc24x7-piloto-governado", "reqsys-dev", "reqsys-dev-selfhosted"})
SHA = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CORRELATION = re.compile(r"[a-zA-Z0-9_.-]{8,128}\Z")
RECEIPT = Path(".tmp/reqsys-dev-readonly-inventory/evidence.json")


class InventoryBlocked(RuntimeError):
    pass


def load_probe():
    source = Path(__file__).with_name("reqsys_dev_current_data_probe.py")
    if source.is_symlink() or not source.is_file():
        raise InventoryBlocked("probe_source_unavailable")
    spec = importlib.util.spec_from_file_location("reqsys_dev_inventory_fixed_probe", source)
    if spec is None or spec.loader is None:
        raise InventoryBlocked("probe_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not all(callable(getattr(module, name, None)) for name in ("collect", "inspected", "validate_dev", "labels", "health")):
        raise InventoryBlocked("probe_contract_invalid")
    return module


def validate_runtime_inputs(environment: dict[str, str], expected_reqsys_sha: str) -> tuple[str, str]:
    runtime_sha = environment.get("GITHUB_SHA", "").lower()
    repo = environment.get("GITHUB_REPOSITORY", "")
    correlation = environment.get("REQSYS_INVENTORY_CORRELATION", "")
    if repo != REPOSITORY or not SHA.fullmatch(runtime_sha):
        raise InventoryBlocked("source_identity_invalid")
    if not SHA.fullmatch(expected_reqsys_sha):
        raise InventoryBlocked("reqsys_target_sha_invalid")
    if not CORRELATION.fullmatch(correlation):
        raise InventoryBlocked("correlation_invalid")
    return runtime_sha, correlation


def sanitize(probe, observed: dict, runtime_sha: str, reqsys_sha: str, correlation: str) -> dict:
    if not isinstance(observed, dict) or observed.get("status") != "observed":
        raise InventoryBlocked("probe_result_invalid")
    if observed.get("host") != HOST or observed.get("source_sha") != runtime_sha:
        raise InventoryBlocked("probe_identity_mismatch")
    project = observed.get("project")
    if project not in PROJECTS:
        raise InventoryBlocked("compose_scope_invalid")
    dialect = (observed.get("configured_database") or {}).get("dialect")
    if dialect not in ("postgresql", "sqlite", "unresolved"):
        raise InventoryBlocked("database_dialect_invalid")
    docker = probe.shutil.which("docker")
    if not docker:
        raise InventoryBlocked("docker_unavailable")
    selected = [(str(observed["gateway"]["service"]), observed["gateway"]["container_id"]),
                ("api", observed["api"]["container_id"])]
    if dialect == "postgresql":
        selected.append(("db", observed["database_container"]["container_id"]))
    frontend = [item for item in observed.get("container_inventory", ())
                if item.get("project") == project and item.get("service") == "frontend"]
    if len(frontend) > 1:
        raise InventoryBlocked("frontend_ambiguous")
    if frontend:
        selected.append(("frontend", frontend[0]["id"]))
    services = []
    for service, identifier in selected:
        item = probe.inspected(docker, identifier)
        probe.validate_dev(item, project, service)
        image = item.get("Image")
        image_id = image if isinstance(image, str) and IMAGE.fullmatch(image) else None
        labels = probe.labels(item)
        config_files = labels.get("com.docker.compose.project.config_files")
        working_dir = labels.get("com.docker.compose.project.working_dir")
        compose_verified = bool(isinstance(config_files, str) and config_files.strip()
                                and isinstance(working_dir, str) and working_dir.strip())
        health = probe.health(item)
        health_value = health.get("health")
        services.append({
            "service": service,
            "image_id": image_id,
            "running": health.get("running") is True,
            "health": health_value if health_value in ("healthy", "unhealthy", "starting", "not_configured") else "unknown",
            "compose_labels_present": compose_verified,
            "compose_labels_sha256": hashlib.sha256((working_dir + "\n" + config_files).encode()).hexdigest() if compose_verified else None,
        })
    build = observed.get("build_info") or {}
    build_sha = build.get("build_sha")
    if not isinstance(build_sha, str) or not SHA.fullmatch(build_sha):
        build_sha = None
    mounts = (observed.get("database_data_mounts") if dialect == "postgresql" else observed.get("api_data_mounts")) or []
    database_volume_persistent = any(isinstance(mount, dict) and mount.get("persistent") is True
                                    for mount in mounts)
    metadata = observed.get("data_metadata") or {}
    db_readonly_verified = bool(dialect == "postgresql" and
                                metadata.get("read_only_transaction") is True and
                                metadata.get("counts_exact") is True)
    reason = "runtime_build_info_unavailable" if build_sha is None else (
        "runtime_sha_drift" if build_sha != reqsys_sha else "runtime_sha_matches")
    receipt = {
        "schema_version": "1.0.0", "status": "observed", "reason_code": reason,
        "host": HOST, "environment": "dev", "repository": REPOSITORY,
        "source_runtime_sha": runtime_sha, "expected_reqsys_sha": reqsys_sha,
        "observed_api_build_sha": build_sha, "api_sha_matches_reqsys": build_sha == reqsys_sha,
        "correlation_id": correlation, "compose_project": project,
        "services": services,
        "image_identities_complete": all(s["image_id"] for s in services),
        "compose_identity_complete": bool(all(s["compose_labels_present"] for s in services)
                                         and len({s["compose_labels_sha256"] for s in services}) == 1),
        "compose_contents_verified": False,
        "gateway_api_route_verified": (observed.get("gateway_api_route") or {}).get("verified") is True,
        "database_dialect": dialect, "database_volume_persistent": database_volume_persistent,
        "database_readonly_metadata_verified": db_readonly_verified,
        "database_consistent_backup_verified": False, "isolated_restore_verified": False,
        "service_rollback_verified": False, "cutover_ready": False,
        "read_only": True, "runtime_mutated": False, "database_rows_exported": False,
        "secrets_exposed": False, "production_touched": False,
    }
    return receipt


def execute(probe, environment: dict[str, str], expected_reqsys_sha: str) -> dict:
    """Return only allowlisted public metadata; never reflect exception text."""
    try:
        runtime_sha, correlation = validate_runtime_inputs(environment, expected_reqsys_sha)
        return sanitize(probe, probe.collect(), runtime_sha, expected_reqsys_sha, correlation)
    except InventoryBlocked as error:
        # Known, fixed categories only; no exception supplied by external processes.
        return {"schema_version": "1.0.0", "status": "blocked", "reason_code": str(error),
                "read_only": True, "runtime_mutated": False, "cutover_ready": False,
                "database_rows_exported": False, "secrets_exposed": False, "production_touched": False}
    except Exception:
        return {"schema_version": "1.0.0", "status": "blocked", "reason_code": "inventory_probe_unavailable",
                "read_only": True, "runtime_mutated": False, "cutover_ready": False,
                "database_rows_exported": False, "secrets_exposed": False, "production_touched": False}


def main() -> int:
    try:
        probe = load_probe()
        result = execute(probe, os.environ, os.environ.get("REQSYS_TARGET_SHA", "").lower())
    except InventoryBlocked as error:
        result = {"schema_version": "1.0.0", "status": "blocked", "reason_code": str(error),
                  "read_only": True, "runtime_mutated": False, "cutover_ready": False,
                  "database_rows_exported": False, "secrets_exposed": False, "production_touched": False}
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
