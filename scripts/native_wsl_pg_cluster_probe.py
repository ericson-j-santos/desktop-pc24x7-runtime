#!/usr/bin/env python3
"""Prova limitada do cluster PostgreSQL WSL: não prova identidade do banco ReqSys.

Somente via Session Launcher + Command Gateway, no SHA exato de main e com
admissão já validada pelo workflow. Nenhum comando ou alvo é configurável.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys

CONTRACT = "native-wsl-pg-cluster-probe-v1"
TARGET_VERSION = "15"
TARGET_NAME = "main"
TARGET_PORT = 5432
MAX_CLUSTERS = 16
MAX_OUTPUT_BYTES = 8192
STATES = frozenset({"online", "online,recovery", "down", "down,demoted"})
PG_READY = {0: "accepting", 1: "rejecting", 2: "no_response", 3: "not_attempted"}
VERSION = re.compile(r"[0-9]{1,2}\Z")
NAME = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
PROVENANCE_FIELDS = frozenset({"host_alias", "source_sha", "rules_sha", "run_id",
                               "correlation_id", "run_attempt", "runner_version"})
FALSE_FIELDS = frozenset({"database_identity_verified", "database_target_qualified",
                           "network_isolation_verified", "backup_restore_verified",
                           "ready_for_installation", "configuration_changed",
                           "credentials_read", "database_contents_read", "cause_proven"})
FIELDS = frozenset({"contract", *PROVENANCE_FIELDS, "status", "target_cluster",
                    "cluster_present", "cluster_status", "cluster_port",
                    "pg_isready_state", "cluster_ready", "read_only", *FALSE_FIELDS})


class ProbeBlocked(ValueError):
    """Razão interna fixa; mensagens cruas do sistema nunca são publicadas."""


def parse_clusters(raw: str) -> dict[str, object]:
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > MAX_OUTPUT_BYTES:
        raise ProbeBlocked("cluster_output_invalid")
    rows = [line for line in raw.splitlines() if line.strip()]
    if len(rows) > MAX_CLUSTERS:
        raise ProbeBlocked("cluster_limit")
    seen: set[tuple[str, str]] = set()
    target: dict[str, object] = {"cluster_present": False, "cluster_status": "absent",
                                 "cluster_port": None}
    for line in rows:
        # -h has no header. Ignore data/log paths and owner; never publish them.
        words = line.split()
        if len(words) < 7:
            raise ProbeBlocked("cluster_row_schema")
        version, name, port_raw, status = words[:4]
        if not VERSION.fullmatch(version) or not NAME.fullmatch(name) or status not in STATES:
            raise ProbeBlocked("cluster_row_invalid")
        if not port_raw.isascii() or not port_raw.isdecimal():
            raise ProbeBlocked("cluster_port_invalid")
        port = int(port_raw)
        if port > 65535 or port < 1:
            raise ProbeBlocked("cluster_port_invalid")
        key = (version, name.casefold())
        if key in seen:
            raise ProbeBlocked("duplicate_cluster")
        seen.add(key)
        if version == TARGET_VERSION and name == TARGET_NAME:
            target = {"cluster_present": True, "cluster_status": status, "cluster_port": port}
    return target


def readiness(code: int) -> str:
    if type(code) is not int or code not in PG_READY:
        raise ProbeBlocked("pg_isready_exit_invalid")
    return PG_READY[code]


def assemble(provenance: dict, clusters: str, ready_code: int) -> dict:
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_FIELDS:
        raise ProbeBlocked("provenance_schema")
    target = parse_clusters(clusters)
    ready = readiness(ready_code)
    report = {
        "contract": CONTRACT, **provenance, "status": "measured",
        "target_cluster": "15/main", **target,
        "pg_isready_state": ready,
        # pg_isready alone may answer for another PostgreSQL instance.
        "cluster_ready": target["cluster_present"] is True
                         and target["cluster_status"] == "online"
                         and target["cluster_port"] == TARGET_PORT
                         and ready == "accepting",
        "read_only": True,
        **{name: False for name in FALSE_FIELDS},
    }
    validate(report)
    return report


def validate(report: dict) -> None:
    if not isinstance(report, dict) or set(report) != FIELDS:
        raise ProbeBlocked("report_schema")
    if report["contract"] != CONTRACT or report["status"] != "measured" or report["target_cluster"] != "15/main":
        raise ProbeBlocked("report_identity")
    if report["host_alias"] != "authorized-primary":
        raise ProbeBlocked("host_invalid")
    if any(type(report[key]) is not str or not SHA.fullmatch(report[key])
           for key in ("source_sha", "rules_sha")):
        raise ProbeBlocked("sha_invalid")
    if type(report["run_attempt"]) is not int or report["run_attempt"] != 1:
        raise ProbeBlocked("attempt_invalid")
    if not isinstance(report["run_id"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", report["run_id"]):
        raise ProbeBlocked("run_invalid")
    if report["correlation_id"] != f"dedicated-runner-{report['run_id']}-1":
        raise ProbeBlocked("correlation_invalid")
    if not isinstance(report["runner_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", report["runner_version"]):
        raise ProbeBlocked("runner_version_invalid")
    if report["cluster_status"] not in STATES | {"absent"}:
        raise ProbeBlocked("cluster_state_invalid")
    if report["pg_isready_state"] not in PG_READY.values():
        raise ProbeBlocked("ready_state_invalid")
    if type(report["cluster_present"]) is not bool or type(report["cluster_ready"]) is not bool or report["read_only"] is not True:
        raise ProbeBlocked("false_success")
    if report["cluster_present"] is False:
        if report["cluster_status"] != "absent" or report["cluster_port"] is not None:
            raise ProbeBlocked("incoherent_absence")
    elif type(report["cluster_port"]) is not int or not 1 <= report["cluster_port"] <= 65535:
        raise ProbeBlocked("cluster_port_invalid")
    qualified = (report["cluster_present"] and report["cluster_status"] == "online"
                 and report["cluster_port"] == TARGET_PORT and report["pg_isready_state"] == "accepting")
    if report["cluster_ready"] is not qualified or any(report[key] is not False for key in FALSE_FIELDS):
        raise ProbeBlocked("false_success")
    if len(json.dumps(report)) > 4096:
        raise ProbeBlocked("report_oversize")


def collect(env: dict, host: str, platform: str, probe_factory=None) -> dict:
    # Runtime deps are only loaded after provenance and prior admission.
    import native_windows_pg_inventory as base
    import native_wsl_pg_qualification as wsl

    try:
        provenance = base.provenance(env, host, platform)
    except (base.InventoryBlocked, TypeError, ValueError):
        raise ProbeBlocked("origin_unverified") from None
    probe = (probe_factory or wsl.WslProbe)()
    try:
        _, clusters = probe._run("/usr/bin/pg_lsclusters", "-h")
        ready_code, _ = probe._run("/usr/bin/pg_isready", "-h", "127.0.0.1",
                                   "-p", str(TARGET_PORT), "-t", "3",
                                   accepted=(0, 1, 2, 3))
    except (wsl.QualificationBlocked, OSError, subprocess.SubprocessError, TypeError, ValueError):
        raise ProbeBlocked("fixed_probe_failed") from None
    return assemble(provenance, clusters, ready_code)


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ProbeBlocked("arguments_rejected")
        import native_windows_pg_inventory as base
        env = {key: os.environ.get(key, "") for key in base.CI_KEYS}
        value = collect(env, socket.gethostname(), sys.platform)
    except (ProbeBlocked, OSError, TypeError, ValueError, subprocess.SubprocessError, ImportError):
        print(json.dumps({"contract": CONTRACT, "status": "blocked"}, sort_keys=True))
        return 3
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
