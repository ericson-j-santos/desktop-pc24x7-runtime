#!/usr/bin/env python3
"""Read-only targeted diagnosis for failed WSL systemd units.

Only bounded systemd properties and sanitized journal evidence codes leave the
host. Raw journal messages, credentials, SQL, configuration and file contents
are never emitted. This probe never repairs, restarts, installs or backs up.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys

try:
    from scripts import native_wsl_systemd_failure_details_probe as details
except ImportError:
    import native_wsl_systemd_failure_details_probe as details

wsl = details.wsl
CONTRACT = "native-wsl-systemd-targeted-diagnosis-v1"
MAX_JOURNAL_RECORDS = 24
MAX_JOURNAL_BYTES = 32768
MAX_EVIDENCE_CODES = 8
DIAG_PROPERTIES = details.PROPERTIES + (
    "UnitFileState",
    "FragmentPath",
    "DropInPaths",
    "NRestarts",
    "StatusText",
    "LoadError",
    "JobResult",
)

CAUSE_PATTERNS = (
    ("address_in_use", re.compile(r"\baddress already in use\b|\bport\b.{0,40}\balready in use\b", re.I)),
    ("authentication_failed", re.compile(r"\bauthentication failed\b|\bpassword authentication failed\b", re.I)),
    ("configuration_invalid", re.compile(r"\binvalid (?:value|configuration|parameter)\b|\bsyntax error\b", re.I)),
    ("database_not_ready", re.compile(r"\bdatabase system is (?:starting|starting up)\b", re.I)),
    ("dependency_failed", re.compile(r"\bdependency failed\b|\bfailed dependency\b", re.I)),
    ("disk_space", re.compile(r"\bno space left on device\b|\bdisk full\b", re.I)),
    ("permission_denied", re.compile(r"\bpermission denied\b|\baccess denied\b", re.I)),
    ("process_exit", re.compile(r"\bexit(?:ed| status| code)\b|\bstatus[=:]\s*\d+\b", re.I)),
    ("protocol_error", re.compile(r"\bprotocol\b", re.I)),
    ("timeout", re.compile(r"\btime(?:d out|out)\b|\btimeout\b", re.I)),
)
EVIDENCE_CODES = tuple(code for code, _ in CAUSE_PATTERNS)
SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:@+/\\ -]{0,160}\Z")


class ProbeBlocked(ValueError):
    """Fail closed without propagating raw host output."""


BLOCK_REASONS = frozenset({
    "unit_name_invalid", "show_output_invalid", "show_output_schema",
    "show_output_property_invalid", "show_output_value_invalid",
    "show_output_incomplete", "journal_output_invalid", "journal_record_limit",
    "journal_schema", "journal_unit_mismatch", "journal_message_invalid",
    "journal_evidence_limit", "origin_unverified", "fixed_probe_failed",
    "invalid_report_schema", "invalid_report_status", "journal_read_not_proven",
    "invalid_failed_units", "invalid_unit_detail", "invalid_journal_evidence",
    "false_success", "report_oversize", "arguments_not_permitted",
    "show_output_id_mismatch",
    *(f"show_output_missing_{name}" for name in DIAG_PROPERTIES),
})


def blocked_report(reason: str) -> dict[str, str]:
    """Expose only a fixed internal reason, never host-provided text."""
    safe_reason = reason if reason in BLOCK_REASONS else "fixed_probe_failed"
    return {"contract": CONTRACT, "reason": safe_reason, "status": "blocked"}


def parse_show_output(unit: str, raw: str) -> dict[str, str]:
    if not details.categories.UNIT.fullmatch(unit):
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
        if key not in DIAG_PROPERTIES or key in values:
            raise ProbeBlocked("show_output_property_invalid")
        if not SAFE_VALUE.fullmatch(value):
            raise ProbeBlocked("show_output_value_invalid")
        values[key] = value
    missing = [name for name in DIAG_PROPERTIES if name not in values]
    if missing:
        raise ProbeBlocked(f"show_output_missing_{missing[0]}")
    if values.get("Id", "").casefold() != unit.casefold():
        raise ProbeBlocked("show_output_id_mismatch")
    return values


def parse_journal(unit: str, raw: str) -> dict[str, object]:
    if not details.categories.UNIT.fullmatch(unit):
        raise ProbeBlocked("unit_name_invalid")
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > MAX_JOURNAL_BYTES:
        raise ProbeBlocked("journal_output_invalid")
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) > MAX_JOURNAL_RECORDS:
        raise ProbeBlocked("journal_record_limit")
    codes: set[str] = set()
    for line in lines:
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            raise ProbeBlocked("journal_schema") from None
        if not isinstance(event, dict) or event.get("_SYSTEMD_UNIT") != unit:
            raise ProbeBlocked("journal_unit_mismatch")
        message = event.get("MESSAGE", "")
        if not isinstance(message, str) or len(message.encode("utf-8", "replace")) > 2048:
            raise ProbeBlocked("journal_message_invalid")
        for code, pattern in CAUSE_PATTERNS:
            if pattern.search(message):
                codes.add(code)
    ordered = [code for code in EVIDENCE_CODES if code in codes]
    if len(ordered) > MAX_EVIDENCE_CODES:
        raise ProbeBlocked("journal_evidence_limit")
    return {"record_count": len(lines), "evidence_codes": ordered}


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
        rows = details.parse_failed_rows(raw)
        diagnosed = []
        for unit, category in rows:
            _, shown = probe._run(
                "/usr/bin/systemctl",
                "show",
                unit,
                "--no-pager",
                *[f"--property={name}" for name in DIAG_PROPERTIES],
            )
            _, journal = probe._run(
                "/usr/bin/journalctl",
                "--unit",
                unit,
                "--no-pager",
                "--output=json",
                "--lines",
                str(MAX_JOURNAL_RECORDS),
                "--quiet",
                "--utc",
            )
            diagnosed.append({
                "unit": unit,
                "category": category,
                "properties": parse_show_output(unit, shown),
                "journal": parse_journal(unit, journal),
            })
    except ProbeBlocked:
        raise
    except (details.wsl.QualificationBlocked, OSError, subprocess.SubprocessError,
            TypeError, ValueError):
        raise ProbeBlocked("fixed_probe_failed") from None
    report = {
        "contract": CONTRACT,
        **provenance,
        "status": "measured",
        "journal_read": True,
        "failed_unit_count": len(diagnosed),
        "failed_units": diagnosed,
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
        "journal_read", "failed_unit_count", "failed_units", "cause_proven",
        "postgresql_modified", "systemd_repaired", "backup_created",
        "deployment_performed", "ready_for_installation",
    }
    if not isinstance(report, dict) or set(report) != fields:
        raise ProbeBlocked("invalid_report_schema")
    if report["contract"] != CONTRACT or report["status"] != "measured":
        raise ProbeBlocked("invalid_report_status")
    if report["journal_read"] is not True:
        raise ProbeBlocked("journal_read_not_proven")
    units = report["failed_units"]
    if (
        not isinstance(units, list)
        or len(units) > details.MAX_FAILED
        or type(report["failed_unit_count"]) is not int
        or report["failed_unit_count"] != len(units)
    ):
        raise ProbeBlocked("invalid_failed_units")
    for item in units:
        if (
            not isinstance(item, dict)
            or set(item) != {"unit", "category", "properties", "journal"}
            or not isinstance(item["unit"], str)
            or not details.categories.UNIT.fullmatch(item["unit"])
            or item["category"] not in details.categories.CATEGORIES
            or not isinstance(item["properties"], dict)
            or set(item["properties"]) != set(DIAG_PROPERTIES)
            or not isinstance(item["journal"], dict)
            or set(item["journal"]) != {"record_count", "evidence_codes"}
        ):
            raise ProbeBlocked("invalid_unit_detail")
        parse_show_output(item["unit"], "\n".join(
            f"{key}={item['properties'][key]}" for key in DIAG_PROPERTIES
        ))
        if (
            type(item["journal"]["record_count"]) is not int
            or not 0 <= item["journal"]["record_count"] <= MAX_JOURNAL_RECORDS
            or not isinstance(item["journal"]["evidence_codes"], list)
            or item["journal"]["evidence_codes"] != [
                code for code in EVIDENCE_CODES
                if code in item["journal"]["evidence_codes"]
            ]
            or len(item["journal"]["evidence_codes"]) > MAX_EVIDENCE_CODES
            or any(code not in EVIDENCE_CODES for code in item["journal"]["evidence_codes"])
        ):
            raise ProbeBlocked("invalid_journal_evidence")
    for key in (
        "cause_proven", "postgresql_modified", "systemd_repaired",
        "backup_created", "deployment_performed", "ready_for_installation",
    ):
        if report[key] is not False:
            raise ProbeBlocked("false_success")
    if len(json.dumps(report)) > 24576:
        raise ProbeBlocked("report_oversize")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ProbeBlocked("arguments_not_permitted")
        environment = {key: os.environ.get(key, "") for key in wsl.base.CI_KEYS}
        result = collect(environment, socket.gethostname(), sys.platform)
    except ProbeBlocked as exc:
        print(json.dumps(blocked_report(str(exc)), sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
