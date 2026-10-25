#!/usr/bin/env python3
"""Bounded WSL qualification for a future native PostgreSQL deployment.

The default WSL distro is started by fixed ``wsl.exe --exec`` probes.  No shell,
package manager, database client connection, credential read, termination, or
configuration mutation is allowed.  Output is intentionally sanitized.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys

import native_windows_pg_inventory as base

CONTRACT = "native-wsl-pg-qualification-v1"
MAX_OUTPUT = 16384
MIN_BACKUP_GIB = 10
MOUNTS = (("root", "/"), ("windows-volume-1", "/mnt/c"),
          ("windows-volume-2", "/mnt/d"))
FILESYSTEMS = {"ext4", "wslfs", "9p", "drvfs", "unknown"}
SYSTEMD_STATES = {"running", "degraded", "maintenance", "starting", "stopping",
                  "offline", "unknown", "unavailable"}
UNIT_STATES = {"loaded", "not-found", "masked", "error", "unknown"}
ACTIVE_STATES = {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
ENABLE_STATES = {"enabled", "disabled", "static", "masked", "indirect", "generated",
                 "transient", "not-found", "unknown"}


class QualificationBlocked(Exception):
    """Fail closed without propagating raw host output."""


class WslProbe:
    def __init__(self, runner=subprocess.run):
        self.runner = runner

    def _run(self, *args: str, accepted=(0,)) -> tuple[int, str]:
        command = ["wsl.exe", "--exec", *args]
        completed = self.runner(command, text=True, capture_output=True, timeout=20,
                                check=False, shell=False)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if len(stdout.encode("utf-8", "replace")) > MAX_OUTPUT or len(
                stderr.encode("utf-8", "replace")) > MAX_OUTPUT:
            raise QualificationBlocked("WSL_OUTPUT_LIMIT")
        if completed.returncode not in accepted:
            raise QualificationBlocked("WSL_FIXED_PROBE_FAILED")
        return completed.returncode, stdout.strip()

    def init_system(self) -> str:
        _, text = self._run("/bin/cat", "/proc/1/comm")
        return "systemd" if text == "systemd" else "other"

    def systemd_state(self) -> str:
        _, text = self._run("/usr/bin/systemctl", "is-system-running", accepted=(0, 1))
        return text if text in SYSTEMD_STATES else "unknown"

    def wsl_conf_systemd(self) -> bool:
        code, text = self._run("/bin/cat", "/etc/wsl.conf", accepted=(0, 1))
        if code == 1:
            return False
        section = ""
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            match = re.fullmatch(r"\[([A-Za-z0-9_-]{1,32})\]", line)
            if match:
                section = match.group(1).casefold()
                continue
            if section == "boot" and re.fullmatch(r"systemd\s*=\s*true", line,
                                                    re.IGNORECASE):
                return True
        return False

    def filesystem(self, alias: str, path: str) -> dict:
        code, fstype = self._run("/usr/bin/findmnt", "-n", "-o", "FSTYPE", path,
                                 accepted=(0, 1))
        if code == 1:
            return {"alias": alias, "present": False, "filesystem": "unknown",
                    "size_gib_floor": 0, "available_gib_floor": 0,
                    "backup_capacity_candidate": False}
        _, text = self._run("/bin/df", "-B1", "--output=size,avail", path)
        rows = [row.split() for row in text.splitlines() if row.strip()]
        if len(rows) != 2 or len(rows[1]) != 2 or not all(item.isdigit() for item in rows[1]):
            raise QualificationBlocked("DF_SCHEMA_REJECTED")
        size, available = map(int, rows[1])
        fs = fstype.casefold() if fstype.casefold() in FILESYSTEMS else "unknown"
        available_gib = available // (1024 ** 3)
        return {"alias": alias, "present": True, "filesystem": fs,
                "size_gib_floor": size // (1024 ** 3),
                "available_gib_floor": available_gib,
                "backup_capacity_candidate": alias != "root" and available_gib >= MIN_BACKUP_GIB}

    def executable(self, path: str) -> bool:
        code, _ = self._run("/usr/bin/test", "-x", path, accepted=(0, 1))
        return code == 0

    def postgresql_unit(self) -> dict:
        code, text = self._run(
            "/usr/bin/systemctl", "show", "postgresql.service", "--no-pager",
            "--property=LoadState", "--property=ActiveState", "--property=UnitFileState",
            accepted=(0, 1, 4),
        )
        if code not in (0, 1, 4):
            raise QualificationBlocked("UNIT_PROBE_FAILED")
        values = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in {"LoadState", "ActiveState", "UnitFileState"}:
                    values[key] = value.casefold()
        load = values.get("LoadState", "unknown")
        active = values.get("ActiveState", "unknown")
        enabled = values.get("UnitFileState", "unknown")
        return {"load_state": load if load in UNIT_STATES else "unknown",
                "active_state": active if active in ACTIVE_STATES else "unknown",
                "enable_state": enabled if enabled in ENABLE_STATES else "unknown"}

    def listeners_5432(self) -> list[dict]:
        code, text = self._run("/usr/bin/ss", "-H", "-ltn", accepted=(0, 127))
        if code == 127:
            return []
        found = set()
        for line in text.splitlines():
            fields = line.split()
            endpoint = fields[3] if len(fields) >= 4 else ""
            if not endpoint.endswith(":5432"):
                continue
            host = endpoint[:-5].strip("[]").casefold()
            family = "ipv6" if ":" in host else "ipv4"
            if host in {"0.0.0.0", "::", "*"}:
                bind = "wildcard"
            elif host in {"127.0.0.1", "::1"}:
                bind = "loopback"
            else:
                bind = "other"
            found.add((family, bind))
        return [{"family": family, "bind": bind} for family, bind in sorted(found)]


def collect(env: dict, host: str, platform: str, probe_factory=WslProbe) -> dict:
    identity = base.provenance(env, host, platform)
    probe = probe_factory()
    init_system = probe.init_system()
    systemd_state = probe.systemd_state() if init_system == "systemd" else "unavailable"
    mounts = [probe.filesystem(alias, path) for alias, path in MOUNTS]
    unit = probe.postgresql_unit() if init_system == "systemd" else {
        "load_state": "unknown", "active_state": "unknown", "enable_state": "unknown"}
    systemd_verified = init_system == "systemd" and systemd_state in SYSTEMD_STATES - {
        "unknown", "unavailable"}
    report = {
        "contract": CONTRACT, **identity, "status": "measured",
        "linux_started": True, "default_distro_only": True,
        "init_system": init_system, "systemd_state": systemd_state,
        "wsl_conf_systemd_enabled": probe.wsl_conf_systemd(),
        "mounts": mounts,
        "postgresql": {"psql_present": probe.executable("/usr/bin/psql"),
                       "cluster_tool_present": probe.executable("/usr/bin/pg_ctlcluster"),
                       "unit": unit, "listeners_5432": probe.listeners_5432()},
        "systemd_verified": systemd_verified,
        "storage_durability_verified": False,
        "restart_verified": False,
        "backup_destination_selected": False,
        "database_target_qualified": False,
        "ready_for_installation": False,
        "database_connected": False,
        "database_contents_read": False,
        "credentials_read": False,
        "configuration_changed": False,
        "packages_installed": False,
        "network_changed": False,
    }
    validate(report)
    return report


def validate(value: dict) -> None:
    expected = {"contract", "host_alias", "source_sha", "rules_sha", "run_id",
                "correlation_id", "run_attempt", "runner_version", "status",
                "linux_started", "default_distro_only", "init_system", "systemd_state",
                "wsl_conf_systemd_enabled", "mounts", "postgresql", "systemd_verified",
                "storage_durability_verified", "restart_verified",
                "backup_destination_selected", "database_target_qualified",
                "ready_for_installation", "database_connected", "database_contents_read",
                "credentials_read", "configuration_changed", "packages_installed",
                "network_changed"}
    if set(value) != expected or value["contract"] != CONTRACT or value["status"] != "measured":
        raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
    if value["init_system"] not in {"systemd", "other"} or value["systemd_state"] not in SYSTEMD_STATES:
        raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
    if len(value["mounts"]) != len(MOUNTS):
        raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
    for row, (alias, _) in zip(value["mounts"], MOUNTS):
        if set(row) != {"alias", "present", "filesystem", "size_gib_floor",
                       "available_gib_floor", "backup_capacity_candidate"} or row["alias"] != alias:
            raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
        if row["filesystem"] not in FILESYSTEMS or type(row["present"]) is not bool:
            raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
        if any(type(row[key]) is not int or row[key] < 0 for key in
               ("size_gib_floor", "available_gib_floor")):
            raise QualificationBlocked("REPORT_SCHEMA_REJECTED")
    if len(json.dumps(value)) > MAX_OUTPUT:
        raise QualificationBlocked("REPORT_TOO_LARGE")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise QualificationBlocked("ARGUMENTS_REJECTED")
        env = {name: os.environ.get(name, "") for name in base.CI_KEYS}
        value = collect(env, socket.gethostname(), sys.platform)
    except (QualificationBlocked, base.InventoryBlocked, OSError, ValueError, TypeError,
            subprocess.SubprocessError):
        print(json.dumps({"contract": CONTRACT, "status": "blocked"}, sort_keys=True))
        return 3
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
