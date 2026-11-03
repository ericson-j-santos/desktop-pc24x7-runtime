#!/usr/bin/env python3
"""Read-only WSL systemd failure details; never repair or deploy.

The fixed failed-unit list and bounded systemctl properties are sanitized before
emission. No journal, credentials, SQL, package manager, restart or configuration
operation is permitted.
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys

try:
    from scripts import native_wsl_systemd_failure_probe as categories
except ImportError:
    import native_wsl_systemd_failure_probe as categories

wsl = categories.wsl
CONTRACT = "native-wsl-systemd-failure-details-v1"
MAX_FAILED = 32
SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:@+/ -]{0,160}\Z")
PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "ConditionResult",
    "AssertResult",
)


class ProbeBlocked(ValueError):
    """Fail closed without propagating raw host output."""


def parse_failed_rows(raw: str) -> list[tuple[str, str]]:
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > 8192:
        raise ProbeBlocked("failed_output_invalid")
    rows = []
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) > MAX_FAILED:
        raise ProbeBlocked("failed_output_limit")
    for row in lines:
        parts = row.split()
        if parts and parts[0] in ("●", "*"):
            parts = parts[1:]
        if len(parts) < 4 or not categories.UNIT.fullmatch(parts[0]):
            raise ProbeBlocked("failed_output_schema")
        if parts[1:4] != ["loaded", "failed", "failed"]:
            raise ProbeBlocked("failed_output_state")
        unit = parts[0].lower()
        category = category_for_unit(unit)
        rows.append((unit, category))
    if len({unit for unit, _ in rows}) != len(rows):
        raise ProbeBlocked("duplicate_failed_unit")
    return rows


def category_for_unit(unit: str) -> str:
    """Use the canonical failed-unit classifier, also on receipt readback."""
    if not isinstance(unit, str) or not categories.UNIT.fullmatch(unit):
        raise ProbeBlocked("unit_name_invalid")
    counts = categories.parse_failed_units(f"{unit} loaded failed failed\n")
    return next(name for name, value in counts.items() if value)


def parse_show_output(unit: str, raw: str) -> dict[str, str]:
    if not categories.UNIT.fullmatch(unit):
        raise ProbeBlocked("unit_name_invalid")
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > 8192:
        raise ProbeBlocked("show_output_invalid")
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            continue
        if "=" not in line:
            raise ProbeBlocked("show_output_schema")
        key, value = line.split("=", 1)
        if key not in PROPERTIES or key in values:
            raise ProbeBlocked("show_output_property_invalid")
        if not SAFE_VALUE.fullmatch(value):
            raise ProbeBlocked("show_output_value_invalid")
        values[key] = value
    if set(values) != set(PROPERTIES) or values.get("Id", "").casefold() != unit.casefold():
        raise ProbeBlocked("show_output_incomplete")
    return values


def collect(env: dict, host: str, platform: str, probe_factory=wsl.WslProbe) -> dict:
    try:
        provenance = wsl.base.provenance(env, host, platform)
    except (wsl.base.InventoryBlocked, TypeError, ValueError):
        raise ProbeBlocked("origin_unverified") from None
    probe = probe_factory()
    try:
        _, raw = probe._run(
            "/usr/bin/systemctl", "--failed", "--no-legend", "--no-pager", "--plain"
        )
        rows = parse_failed_rows(raw)
        details = []
        for unit, category in rows:
            _, shown = probe._run(
                "/usr/bin/systemctl",
                "show",
                unit,
                "--no-pager",
                *[f"--property={name}" for name in PROPERTIES],
            )
            details.append({
                "unit": unit,
                "category": category,
                "properties": parse_show_output(unit, shown),
            })
    except (wsl.QualificationBlocked, OSError, TypeError, ValueError):
        raise ProbeBlocked("fixed_probe_failed") from None
    report = {
        "contract": CONTRACT,
        **provenance,
        "status": "measured",
        "failed_unit_count": len(details),
        "failed_units": details,
        "cause_proven": False,
        "postgresql_modified": False,
        "systemd_repaired": False,
        "backup_created": False,
        "deployment_performed": False,
        "ready_for_installation": False,
    }
    validate(report)
    return report


def validate(report: dict) -> None:
    fields = {
        "contract", "host_alias", "source_sha", "rules_sha", "run_id",
        "correlation_id", "run_attempt", "runner_version", "status",
        "failed_unit_count", "failed_units", "cause_proven",
        "postgresql_modified", "systemd_repaired", "backup_created",
        "deployment_performed", "ready_for_installation",
    }
    if not isinstance(report, dict) or set(report) != fields:
        raise ProbeBlocked("invalid_report_schema")
    if report["contract"] != CONTRACT or report["status"] != "measured":
        raise ProbeBlocked("invalid_report_status")
    units = report["failed_units"]
    if (
        not isinstance(units, list)
        or len(units) > MAX_FAILED
        or type(report["failed_unit_count"]) is not int
        or report["failed_unit_count"] != len(units)
    ):
        raise ProbeBlocked("invalid_failed_units")
    seen_units: set[str] = set()
    for item in units:
        if (
            not isinstance(item, dict)
            or set(item) != {"unit", "category", "properties"}
            or not isinstance(item["unit"], str)
            or not categories.UNIT.fullmatch(item["unit"])
            or item["category"] not in categories.CATEGORIES
            or not isinstance(item["properties"], dict)
            or set(item["properties"]) != set(PROPERTIES)
        ):
            raise ProbeBlocked("invalid_unit_detail")
        normalized = item["unit"].casefold()
        if normalized in seen_units:
            raise ProbeBlocked("duplicate_failed_unit")
        seen_units.add(normalized)
        if item["category"] != category_for_unit(item["unit"]):
            raise ProbeBlocked("unit_category_mismatch")
        parse_show_output(item["unit"], "\n".join(
            f"{key}={item['properties'][key]}" for key in PROPERTIES
        ))
    for key in (
        "cause_proven", "postgresql_modified", "systemd_repaired",
        "backup_created", "deployment_performed", "ready_for_installation",
    ):
        if report[key] is not False:
            raise ProbeBlocked("false_success")
    if len(json.dumps(report)) > 16384:
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
