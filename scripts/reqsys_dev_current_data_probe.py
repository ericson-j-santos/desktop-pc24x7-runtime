#!/usr/bin/env python3
"""Read-only metadata of the existing ReqSys DEV gateway and its data source.

Fixed Desktop / port 8083. Never changes containers, data, files of the live
application, credentials or routes. Counts and schema metadata only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import unquote, urlsplit
import urllib.error
import urllib.request

HOST = "DESKTOP-PDQK954"
PROJECTS = {"wt-pc24x7-piloto", "wt-pc24x7-piloto-governado", "reqsys-dev", "reqsys-dev-selfhosted"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
MAX_TABLES = 200
LIST_FORMAT = (
    '{{printf "{\\"id\\":%q,\\"name\\":%q,\\"project\\":%q,\\"service\\":%q,'
    '\\"published_ports\\":%q,\\"state\\":%q,\\"status\\":%q}" .ID .Names '
    '(.Label "com.docker.compose.project") (.Label "com.docker.compose.service") '
    '.Ports .State .Status}}'
)
PG_SQL = """
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '3s';
WITH tables AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p')
 ORDER BY c.relname LIMIT 201
), counts AS (
 SELECT table_name,
 (xpath('/row/n/text()',query_to_xml(
  format('SELECT count(*) AS n FROM %I.%I',schema_name,table_name),
  false,true,'')))[1]::text::bigint AS rows
 FROM tables
), modifications AS (
 SELECT relname,n_tup_ins,n_tup_upd,n_tup_del
 FROM pg_stat_user_tables WHERE schemaname='public'
)
SELECT jsonb_build_object(
 'database',current_database(),'role',current_user,
 'server_version',current_setting('server_version'),
 'is_in_recovery',pg_is_in_recovery(),
 'wal_lsn',(CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn() ELSE pg_current_wal_lsn() END)::text,
 'system_identifier',CASE WHEN has_function_privilege(current_user,'pg_control_system()','EXECUTE')
 THEN (SELECT system_identifier::text FROM pg_control_system()) ELSE NULL END,
 'transaction_snapshot',txid_current_snapshot()::text,
 'observed_at',clock_timestamp(),
 'table_counts',COALESCE((SELECT jsonb_object_agg(table_name,rows) FROM counts),'{}'::jsonb),
 'table_limit_exceeded',(SELECT count(*) FROM tables)>200,
 'modification_stats',COALESCE((SELECT jsonb_object_agg(relname,jsonb_build_object(
  'inserts',n_tup_ins,'updates',n_tup_upd,'deletes',n_tup_del)) FROM modifications),'{}'::jsonb)
);
COMMIT;
"""


class ProbeFailure(RuntimeError):
    pass


def run(args, timeout=20):
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", stdin=subprocess.DEVNULL,
                                timeout=timeout, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeFailure("command_unavailable_or_timeout") from None
    if result.returncode:
        raise ProbeFailure("readonly_command_failed")
    if len(result.stdout) > 2097152:
        raise ProbeFailure("metadata_response_too_large")
    return result.stdout


def inspected(docker, identifier):
    if not CONTAINER_ID.fullmatch(identifier):
        raise ProbeFailure("invalid_container_id")
    try:
        result = json.loads(run([docker, "inspect", identifier]))
    except ValueError:
        raise ProbeFailure("container_metadata_invalid") from None
    if not isinstance(result, list) or len(result) != 1 or result[0].get("Id") != identifier:
        raise ProbeFailure("container_identity_changed")
    return result[0]


def environment(item):
    result = {}
    # Inspect only in memory; none of these raw values enter evidence/errors.
    for value in (item.get("Config") or {}).get("Env") or []:
        key, separator, raw = value.partition("=")
        if separator:
            result[key] = raw
    return result


def labels(item):
    return (item.get("Config") or {}).get("Labels") or {}


def host_port(item, wanted):
    return any(str(binding.get("HostPort")) == str(wanted)
               for bindings in ((item.get("NetworkSettings") or {}).get("Ports") or {}).values()
               for binding in bindings or [])


def validate_dev(item, project, service):
    if project not in PROJECTS:
        raise ProbeFailure("unapproved_dev_project")
    if labels(item).get("com.docker.compose.project") != project:
        raise ProbeFailure("compose_project_changed")
    if labels(item).get("com.docker.compose.service") != service:
        raise ProbeFailure("compose_service_changed")
    if not (item.get("State") or {}).get("Running"):
        raise ProbeFailure("owned_container_not_running")
    context = environment(item)
    app_env = context.get("APP_ENV", context.get("ENVIRONMENT", "development")).casefold()
    if app_env not in {"development", "dev", "local", ""}:
        raise ProbeFailure("non_dev_environment_blocked")


def health(item):
    state = item.get("State") or {}
    return {"running": bool(state.get("Running")),
            "health": str((state.get("Health") or {}).get("Status") or "not_configured")}


def data_mounts(item):
    result = []
    for mount in item.get("Mounts") or []:
        if mount.get("Destination") not in {"/app", "/data", "/var/lib/postgresql/data"}:
            continue
        result.append({"destination": mount["Destination"], "type": mount.get("Type"),
                       "persistent": mount.get("Type") in {"bind", "volume"},
                       "writable": bool(mount.get("RW"))})
    return result


def configured_database(item):
    raw = environment(item).get("DATABASE_URL")
    if raw is None:
        return {"dialect": "unresolved", "configuration_source": "DATABASE_URL_not_in_container_env"}
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.split("+", 1)[0].lower()
        if scheme == "postgresql":
            database = unquote(parsed.path.lstrip("/"))
            role = unquote(parsed.username or "")
            if not IDENTIFIER.fullmatch(database) or not IDENTIFIER.fullmatch(role):
                raise ProbeFailure("database_identity_unapproved")
            if parsed.hostname != "db" or parsed.port not in (None, 5432):
                raise ProbeFailure("database_host_unapproved")
            return {"dialect": "postgresql", "database": database, "role": role,
                    "configuration_source": "container_environment"}
        if scheme == "sqlite":
            prefix = parsed.scheme + ":///"
            if not raw.startswith(prefix):
                raise ProbeFailure("sqlite_url_unapproved")
            path = unquote(raw[len(prefix):].split("?", 1)[0])
            base = (item.get("Config") or {}).get("WorkingDir") or "/app"
            container_path = PurePosixPath(path) if path.startswith("/") else PurePosixPath(base) / path
            if str(container_path) not in {"/app/reqsys.db", "/data/reqsys.db"}:
                raise ProbeFailure("sqlite_path_unapproved")
            return {"dialect": "sqlite", "container_path": str(container_path),
                    "configuration_source": "container_environment"}
    except (ValueError, TypeError):
        raise ProbeFailure("database_configuration_invalid") from None
    raise ProbeFailure("database_dialect_unapproved")


def shared_db_network(api, database):
    api_networks = (api.get("NetworkSettings") or {}).get("Networks") or {}
    db_networks = (database.get("NetworkSettings") or {}).get("Networks") or {}
    return any(name in api_networks and details.get("NetworkID")
               == api_networks[name].get("NetworkID")
               and "db" in (details.get("Aliases") or [])
               for name, details in db_networks.items())


def postgres_metadata(docker, database, identity):
    env = environment(database)
    role = env.get("POSTGRES_USER", "postgres")
    name = env.get("POSTGRES_DB", role)
    if not IDENTIFIER.fullmatch(role) or not IDENTIFIER.fullmatch(name):
        raise ProbeFailure("postgres_identity_unapproved")
    if name != identity["database"]:
        raise ProbeFailure("postgres_database_mismatch")
    identifier = database["Id"]
    command = [docker, "exec", identifier, "psql", "--no-psqlrc", "--no-password",
               "--username", role, "--dbname", name, "--set", "ON_ERROR_STOP=1",
               "--set", "VERBOSITY=terse", "--tuples-only", "--no-align",
               "--command", PG_SQL]
    raw = run(command, timeout=25)
    try:
        lines = [line for line in raw.splitlines() if line.strip().startswith("{")]
        if len(lines) != 1:
            raise ProbeFailure("postgres_metadata_invalid")
        payload = json.loads(lines[0])
    except ValueError:
        raise ProbeFailure("postgres_metadata_invalid") from None
    if payload.get("database") != name or payload.get("role") != role:
        raise ProbeFailure("postgres_readback_identity_mismatch")
    counts = payload.get("table_counts")
    if not isinstance(counts, dict) or len(counts) > MAX_TABLES or payload.get("table_limit_exceeded"):
        raise ProbeFailure("postgres_table_limit_exceeded")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts.values()):
        raise ProbeFailure("postgres_counts_invalid")
    payload["counts_exact"] = True
    payload["rows_exported"] = False
    payload["read_only_transaction"] = True
    payload["data_freshness_proven"] = False
    payload["modification_stats_may_lag"] = True
    return payload


def nginx_api_route(docker, gateway, api):
    image = str((gateway.get("Config") or {}).get("Image") or "")
    if not re.search(r"(?:^|/)nginx(?::|@)", image):
        return {"verified": False, "reason": "nginx_image_identity_unapproved"}
    try:
        configuration = run([docker, "exec", gateway["Id"], "nginx", "-T"], timeout=10)
        locations = []
        for match in re.finditer(r"\blocation\s+(?:\^~\s+)?(/api/?)\s*\{", configuration):
            start = match.end()
            position = start
            level = 1
            while position < len(configuration) and level:
                level += (configuration[position] == "{") - (configuration[position] == "}")
                position += 1
            if level:
                raise ProbeFailure("nginx_location_parse_failed")
            locations.append(configuration[start:position-1])
        if len(locations) != 1:
            return {"verified": False, "reason": "nginx_api_location_not_unique"}
        targets = re.findall(r"\bproxy_pass\s+(https?://[^\s;]+)\s*;", locations[0])
        if len(targets) != 1:
            return {"verified": False, "reason": "nginx_api_proxy_not_unique"}
        target = urlsplit(targets[0])
        if target.username or target.password or target.scheme != "http":
            return {"verified": False, "reason": "nginx_api_proxy_identity_unapproved"}
        if target.hostname == "api" and target.port == 8000:
            routed = True
        else:
            upstreams = re.findall(r"\bupstream\s+" + re.escape(target.hostname or "")
                                   + r"\s*\{([^{}]*)\}", configuration)
            servers = re.findall(r"\bserver\s+([^\s;]+)", upstreams[0]) if len(upstreams) == 1 else []
            routed = target.port is None and servers == ["api:8000"]
        gateway_networks = (gateway.get("NetworkSettings") or {}).get("Networks") or {}
        api_networks = (api.get("NetworkSettings") or {}).get("Networks") or {}
        shared = any(name in gateway_networks and network.get("NetworkID")
                     == gateway_networks[name].get("NetworkID")
                     and "api" in (network.get("Aliases") or [])
                     for name, network in api_networks.items())
        return {"verified": bool(routed and shared),
                "target_service": "api" if routed else None,
                "target_port": 8000 if routed else None,
                "shared_owned_network": bool(shared),
                "configuration_values_exported": False}
    except (ProbeFailure, ValueError, TypeError):
        return {"verified": False, "reason": "nginx_api_route_unresolved"}


def windows_bind_path(raw):
    for prefix in ("/run/desktop/mnt/host/", "/host_mnt/"):
        if raw.casefold().startswith(prefix):
            drive, separator, tail = raw[len(prefix):].partition("/")
            if separator and len(drive) == 1 and drive.isalpha():
                return Path(drive.upper() + ":/" + tail)
    return Path(raw)


def allowed_local_database(path):
    resolved = path.resolve()
    parts = PureWindowsPath(str(resolved)).parts
    if len(parts) < 4 or parts[0].casefold() != "c:\\" or parts[1].casefold() != "dev":
        raise ProbeFailure("sqlite_host_mount_outside_allowed_root")
    root = parts[2].casefold()
    if root != "reqsys-v2-enterprise-real" and not root.startswith("wt-") and root != "chatgpt-workers":
        raise ProbeFailure("sqlite_host_mount_outside_allowed_root")
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
            raise ProbeFailure("sqlite_reparse_path_blocked")
    if not resolved.is_file() or resolved.stat().st_size > 67108864:
        raise ProbeFailure("sqlite_source_missing_or_too_large")
    return resolved


def sqlite_metadata(api, identity):
    relative = PurePosixPath(identity["container_path"])
    matches = []
    for mount in api.get("Mounts") or []:
        if mount.get("Type") != "bind":
            continue
        destination = PurePosixPath(mount.get("Destination", ""))
        if relative.is_relative_to(destination):
            source = windows_bind_path(str(mount.get("Source") or ""))
            matches.append(source.joinpath(*relative.relative_to(destination).parts))
    if len(matches) != 1:
        raise ProbeFailure("sqlite_readonly_host_mount_not_unique")
    source = allowed_local_database(matches[0])
    before = source.stat()
    started = time.monotonic()
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            if time.monotonic() - started > 15:
                raise ProbeFailure("sqlite_hash_timeout")
            digest.update(block)
    after = source.stat()
    changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    # Do not open a live SQLite connection. Even mode=ro can write WAL -shm.
    # A live file digest excludes WAL and cannot prove backup freshness.
    return {"observed_at": datetime.now(timezone.utc).isoformat(),
            "live_file_sha256": digest.hexdigest(), "bytes": after.st_size,
            "file_changed_during_hash": changed,
            "wal_present": Path(str(source) + "-wal").exists(),
            "shm_present": Path(str(source) + "-shm").exists(),
            "sha256_semantics": "live_main_file_excludes_wal_not_a_snapshot",
            "counts_available": False, "reason": "consistent_online_snapshot_required",
            "rows_exported": False, "sqlite_connection_opened": False,
            "temporary_database_files_written": False, "data_freshness_proven": False}


def build_info():
    try:
        request = urllib.request.Request("http://127.0.0.1:8083/api/runtime/build-info",
                                         headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read(262145))
            status = response.status
        data = payload.get("data", payload)
        sha = data.get("build_sha")
        return {"http_status": status, "build_sha": sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) else None}
    except (ValueError, AttributeError, OSError, urllib.error.URLError):
        return {"http_status": None, "build_sha": None, "error_code": "build_info_unavailable"}


def require_host():
    if os.name != "nt" or socket.gethostname().casefold() != HOST.casefold():
        raise ProbeFailure("desktop_host_required")
    if os.environ.get("GITHUB_REPOSITORY") not in {
        "ericson-j-santos/desktop-pc24x7-runtime",
        "ericson-j-santos/reqsys-v2-enterprise-real",
    }:
        raise ProbeFailure("repository_unapproved")


def collect():
    require_host()
    docker = shutil.which("docker")
    if not docker:
        raise ProbeFailure("docker_missing")
    lines = run([docker, "ps", "--all", "--no-trunc", "--format", LIST_FORMAT]).splitlines()
    if len(lines) > 100:
        raise ProbeFailure("container_inventory_limit_exceeded")
    containers = [json.loads(line) for line in lines if line.strip()]
    owners = []
    for candidate in containers:
        if candidate.get("state") != "running" or "8083->" not in candidate.get("published_ports", ""):
            continue
        item = inspected(docker, candidate["id"])
        if host_port(item, 8083):
            owners.append(item)
    if len(owners) != 1:
        raise ProbeFailure("gateway_8083_not_unique")
    gateway = owners[0]
    project = labels(gateway).get("com.docker.compose.project")
    service = labels(gateway).get("com.docker.compose.service")
    if service not in {"nginx", "gateway", "caddy"}:
        raise ProbeFailure("gateway_service_unapproved")
    validate_dev(gateway, project, service)
    candidates = [item for item in containers if item.get("project") == project and item.get("service") == "api"]
    if len(candidates) != 1:
        raise ProbeFailure("owned_api_not_unique")
    api = inspected(docker, candidates[0]["id"])
    validate_dev(api, project, "api")
    identity = configured_database(api)
    result = {"schema_version": "1.0.0", "phase": "current_dev_data_readonly_probe",
              "host": HOST, "project": project,
              "observed_at": datetime.now(timezone.utc).isoformat(),
              "source_sha": os.environ.get("REQSYS_SOURCE_SHA", os.environ.get("GITHUB_SHA")),
              "container_inventory": containers,
              "gateway": {"container_id": gateway["Id"], "service": service, **health(gateway)},
              "api": {"container_id": api["Id"], "service": "api", **health(api)},
              "configured_database": identity, "api_data_mounts": data_mounts(api),
              "build_info": build_info(), "gateway_api_route": nginx_api_route(docker, gateway, api),
              "credentials_logged": False,
              "secret_files_read": False, "database_rows_exported": False,
              "services_changed": False, "routes_changed": False,
              "cutover_ready": False}
    if identity["dialect"] == "postgresql":
        candidates = [item for item in containers if item.get("project") == project and item.get("service") == "db"]
        if len(candidates) != 1:
            raise ProbeFailure("owned_database_not_unique")
        database = inspected(docker, candidates[0]["id"])
        validate_dev(database, project, "db")
        if not shared_db_network(api, database):
            raise ProbeFailure("owned_database_network_mismatch")
        result["database_container"] = {"container_id": database["Id"], **health(database)}
        result["database_data_mounts"] = data_mounts(database)
        try:
            result["data_metadata"] = postgres_metadata(docker, database, identity)
        except ProbeFailure as error:
            result["data_metadata"] = {"available": False, "error_code": str(error), "data_freshness_proven": False}
        result["sqlite_backup_is_current_source"] = False
    elif identity["dialect"] == "sqlite":
        try:
            result["data_metadata"] = sqlite_metadata(api, identity)
        except ProbeFailure as error:
            result["data_metadata"] = {"available": False, "error_code": str(error), "data_freshness_proven": False}
        result["sqlite_backup_is_current_source"] = None
    else:
        result["data_metadata"] = {"available": False, "reason": "effective_database_unresolved"}
    result["status"] = "observed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = collect()
    except ProbeFailure as error:
        result = {"schema_version": "1.0.0", "status": "blocked", "error_code": str(error),
                  "services_changed": False, "routes_changed": False, "cutover_ready": False}
    except Exception:
        result = {"schema_version": "1.0.0", "status": "blocked", "error_code": "metadata_probe_failed",
                  "services_changed": False, "routes_changed": False, "cutover_ready": False}
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_file.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
