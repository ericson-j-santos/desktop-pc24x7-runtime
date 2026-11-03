#!/usr/bin/env python3
"""Probe fixed failed-systemd categories in Desktop WSL; read-only, never deploy.

Only sanitized category counts leave this script. Origin is qualified by the
existing physical runner provenance guard before the first WSL call.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys

try:
    from scripts import native_wsl_pg_qualification as wsl
except ImportError:
    import native_wsl_pg_qualification as wsl

CONTRACT = "native-wsl-systemd-failure-probe-v1"
MAX_FAILED = 32
CATEGORIES = ("postgresql", "legacy_container", "network", "systemd", "other")
UNIT = re.compile(r"[a-zA-Z0-9_.@:-]{1,120}\.(service|mount|socket|device|target|timer|path)\Z")


class ProbeBlocked(ValueError):
    pass


def parse_failed_units(raw: str) -> dict[str, int]:
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > 8192:
        raise ProbeBlocked("failed_output_invalid")
    counts = {key: 0 for key in CATEGORIES}
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) > MAX_FAILED:
        raise ProbeBlocked("failed_output_limit")
    for row in lines:
        parts = row.split()
        if parts and parts[0] in ("●", "*"):
            parts = parts[1:]
        if len(parts) < 4 or not UNIT.fullmatch(parts[0]):
            raise ProbeBlocked("failed_output_schema")
        if parts[1:4] != ["loaded", "failed", "failed"]:
            raise ProbeBlocked("failed_output_state")
        name = parts[0].lower()
        suffix = name.rsplit(".", 1)[1]
        if name.startswith(("postgresql", "postgres-")):
            category = "postgresql"
        elif name.startswith(("docker", "containerd", "podman", "cri-", "libpod")):
            category = "legacy_container"
        elif name.startswith(("systemd-network", "networking", "systemd-resolved",
                              "networkmanager")):
            category = "network"
        elif suffix in ("mount", "device") or name.startswith(("systemd-", "wsl")):
            category = "systemd"
        else:
            category = "other"
        counts[category] += 1
    return counts


def collect(env: dict, host: str, platform: str, probe_factory=wsl.WslProbe) -> dict:
    try:
        provenance = wsl.base.provenance(env, host, platform)
    except (wsl.base.InventoryBlocked, TypeError, ValueError):
        raise ProbeBlocked("origin_unverified") from None
    probe = probe_factory()
    try:
        _, raw = probe._run("/usr/bin/systemctl", "--failed",
                            "--no-legend", "--no-pager", "--plain")
        categories = parse_failed_units(raw)
    except (wsl.QualificationBlocked, subprocess.SubprocessError, OSError,
            TypeError, ValueError):
        raise ProbeBlocked("fixed_probe_failed") from None
    first = next((key for key in CATEGORIES if categories[key]), "none_observed")
    report = {
        "contract": CONTRACT, **provenance, "status": "measured",
        "failed_unit_count": sum(categories.values()),
        "categories": categories, "first_category": first,
        "cause_proven": False, "postgresql_modified": False,
        "systemd_repaired": False, "backup_created": False,
        "deployment_performed": False, "ready_for_installation": False,
    }
    validate(report)
    return report


def validate(report: dict) -> None:
    fields = {"contract", "host_alias", "source_sha", "rules_sha", "run_id",
              "correlation_id", "run_attempt", "runner_version", "status",
              "failed_unit_count", "categories", "first_category",
              "cause_proven", "postgresql_modified", "systemd_repaired",
              "backup_created", "deployment_performed", "ready_for_installation"}
    if not isinstance(report, dict) or set(report) != fields:
        raise ProbeBlocked("invalid_report_schema")
    if report["contract"] != CONTRACT or report["status"] != "measured":
        raise ProbeBlocked("invalid_report_status")
    c = report["categories"]
    if (not isinstance(c, dict) or set(c) != set(CATEGORIES) or
        any(type(c[k]) is not int or not 0 <= c[k] <= MAX_FAILED for k in CATEGORIES) or
        type(report["failed_unit_count"]) is not int or
        report["failed_unit_count"] != sum(c.values()) or
        report["failed_unit_count"] > MAX_FAILED or
        report["first_category"] not in (*CATEGORIES, "none_observed")):
        raise ProbeBlocked("invalid_counts")
    expected_first = next((key for key in CATEGORIES if c[key] > 0), "none_observed")
    if report["first_category"] != expected_first:
        raise ProbeBlocked("incoherent_first_category")
    for key in ("cause_proven", "postgresql_modified", "systemd_repaired",
                "backup_created", "deployment_performed", "ready_for_installation"):
        if report[key] is not False:
            raise ProbeBlocked("false_success")
    if len(json.dumps(report)) > 4096:
        raise ProbeBlocked("report_oversize")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ProbeBlocked("arguments_not_permitted")
        environment = {key: os.environ.get(key, "") for key in wsl.base.CI_KEYS}
        result = collect(environment, socket.gethostname(), sys.platform)
    except ProbeBlocked:
        print(json.dumps({"contract": CONTRACT, "status": "blocked"}, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
