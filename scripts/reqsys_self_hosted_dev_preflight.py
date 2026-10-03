#!/usr/bin/env python3
"""Read-only, fixed-host facts for the ReqSys DEV migration."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import urllib.error
import urllib.request

HOST = "DESKTOP-PDQK954"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
PROJECT = "reqsys-dev-selfhosted"

def docker(arguments: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(["docker", *arguments], capture_output=True,
                                   text=True, timeout=30, check=False)
        return completed.returncode == 0, completed.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, ""

def http_facts(port: int) -> dict:
    facts = {"port": port, "health": False, "auth_configured": False}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for suffix in ["/api/health", "/health"]:
        try:
            with opener.open(f"http://127.0.0.1:{port}{suffix}", timeout=5) as response:
                facts["health"] = response.status == 200
            if facts["health"]:
                break
        except (OSError, urllib.error.URLError):
            pass
    try:
        with opener.open(f"http://127.0.0.1:{port}/api/v1/auth/config", timeout=5) as response:
            data = json.loads(response.read(65536))
            payload = data.get("data", data)
            facts["auth_configured"] = bool(payload.get("azure_tenant_id") and payload.get("azure_client_id"))
            facts["auth_status"] = str(payload.get("auth_status", "unknown"))[:40]
    except (OSError, ValueError, TypeError, AttributeError):
        facts["auth_status"] = "unavailable"
    return facts

def backup_facts() -> dict:
    # Metadata only; passwords, repository objects and row values are never read.
    root = Path(os.environ["LOCALAPPDATA"]) / "ReqSys" / "MigrationBackups" / "20261002-1912"
    facts = {"expected_backup_directory_present": root.is_dir(),
             "manifest_present": (root / "reqsys-dev-manifest.json").is_file(),
             "validated_sqlite_present": False}
    for name in ("reqsys-dev.sqlite", "reqsys-dev.db", "source.db", "reqsys.db"):
        file = root / name
        if file.is_file() and not file.is_symlink():
            facts["validated_sqlite_present"] = True
    return facts

def collect() -> dict:
    host = socket.gethostname()
    if (host.casefold() != HOST.casefold()
        or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("RUNNER_NAME") != "DESKTOP-PDQK954-runtime"):
        raise RuntimeError("FIXED_HOST_OR_RUNNER_MISMATCH")
    result = {"schema_version": 1, "host": host, "project": PROJECT,
              "source_sha": os.environ.get("GITHUB_SHA", ""),
              "correlation_id": os.environ.get("CORRELATION_ID", ""),
              "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "phase": "preflight", "deployment_completed": False,
              "restore_verified": False, "dev_route_changed": False}
    if not shutil.which("docker"):
        result["docker"] = {"available": False, "linux_engine": False}
    else:
        ok, output = docker(["version", "--format", "{{.Server.Os}}"])
        compose_ok, compose_version = docker(["compose", "version", "--short"])
        result["docker"] = {"available": ok, "linux_engine": ok and output == "linux",
                            "compose_available": compose_ok,
                            "compose_version": compose_version if re.fullmatch(r"[v\d.]+", compose_version) else "unknown"}
        ps_ok, output = docker(["ps", "--all", "--format", "{{json .}}"])
        containers = []
        if ps_ok:
            for line in output.splitlines():
                try:
                    item = json.loads(line)
                    name = item.get("Names", "")
                    if re.fullmatch(r"[\w.-]{1,128}", name) and ("reqsys" in name.lower() or "gateway" in name.lower()):
                        containers.append({"name": name, "state": item.get("State", "unknown"),
                                           "ports": str(item.get("Ports", ""))[:512]})
                except (ValueError, AttributeError):
                    pass
        result["containers"] = containers
        result["isolated_project_exists"] = any(c["name"].startswith(PROJECT + "-") for c in containers)
    result["legacy_private_inputs"] = {
        "configuration_exists": Path(r"C:\ReqSys\dev\runtime.env").is_file(),
        "three_secret_files_present": all((Path(r"C:\ReqSys\dev\secrets") / n).is_file()
            for n in ("db_owner_password", "db_app_password", "jwt_secret"))}
    result["local_backup"] = backup_facts()
    result["endpoints"] = [http_facts(port) for port in (8083, 18080)]
    result["blockers"] = []
    if not result["docker"].get("linux_engine"):
        result["blockers"].append("DOCKER_LINUX_ENGINE_UNAVAILABLE")
    if not result["docker"].get("compose_available"):
        result["blockers"].append("COMPOSE_UNAVAILABLE")
    if not result["local_backup"]["validated_sqlite_present"]:
        result["blockers"].append("VALIDATED_SQLITE_NOT_PRESENT_AT_FIXED_BACKUP_LOCATION")
    result["status"] = "facts_collected"
    return result

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    evidence = collect()
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_file.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
