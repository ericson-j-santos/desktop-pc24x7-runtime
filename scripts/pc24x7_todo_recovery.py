"""Offline-checkable, provider-independent TODO backup and isolated restore.

No provider API, deployment, worker, credential generation, CREATE/DROP DATABASE,
source mutation or cutover. On user hosts, invoke only through Session/Gateway.
PostgreSQL tools and service/password files are supplied by the approved executor.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import queue
import re
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = "todo_bus"
IDENT = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED = {"queue_events", "continuation_requests"}
SOURCE_DATABASES = {"todo_global_bus_dev", "todo_global_bus_dev_ha"}
LOCAL_HOSTS = {"127.0.0.1", "::1"}
TABLES_SQL = """SELECT coalesce(json_agg(tablename ORDER BY tablename),'[]'::json)
FROM pg_tables WHERE schemaname='todo_bus'"""
IDENTITY_SQL = """SELECT json_build_object('database',current_database(),
'major',current_setting('server_version_num')::int/10000,
'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user))"""


class RecoveryBlocked(RuntimeError):
    """A stable, non-sensitive reason suitable for an operational receipt."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise RecoveryBlocked("REGULAR_FILE_REQUIRED")


def service(name: str, env: dict[str, str], *, target: bool) -> dict[str, str]:
    if name not in {"todo_recovery_source", "todo_recovery_target"}:
        raise RecoveryBlocked("SERVICE_NOT_ALLOWED")
    if (name == "todo_recovery_target") != target:
        raise RecoveryBlocked("SERVICE_ROLE_MISMATCH")
    filename = env.get("PGSERVICEFILE", "")
    if not filename:
        raise RecoveryBlocked("PROTECTED_SERVICE_FILE_REQUIRED")
    path = Path(filename)
    regular(path)
    password_file = env.get("PGPASSFILE", "")
    if not password_file:
        raise RecoveryBlocked("PROTECTED_PASSWORD_FILE_REQUIRED")
    regular(Path(password_file))
    if os.name != "nt" and (Path(password_file).stat().st_mode & 0o077):
        raise RecoveryBlocked("PASSWORD_FILE_PERMISSIONS_UNSAFE")
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(path, encoding="utf-8")
    if name not in cfg or cfg.defaults():
        raise RecoveryBlocked("SERVICE_PROFILE_INVALID")
    values = dict(cfg[name])
    allowed = {"host", "port", "dbname", "user", "sslmode", "sslrootcert"}
    if set(values) - allowed or not {"host", "port", "dbname", "user"} <= set(values):
        raise RecoveryBlocked("SERVICE_PROFILE_INVALID")
    if not values["port"].isdigit() or not 1 <= int(values["port"]) <= 65535:
        raise RecoveryBlocked("SERVICE_PORT_INVALID")
    if not IDENT.fullmatch(values["dbname"]):
        raise RecoveryBlocked("DATABASE_NAME_INVALID")
    if target:
        if values["host"] not in LOCAL_HOSTS or not values["dbname"].startswith("todo_restore_"):
            raise RecoveryBlocked("ISOLATED_LOCAL_TARGET_REQUIRED")
    elif values["dbname"] not in SOURCE_DATABASES:
        raise RecoveryBlocked("SOURCE_DATABASE_NOT_ALLOWED")
    elif values["host"] not in LOCAL_HOSTS and values.get("sslmode") != "verify-full":
        raise RecoveryBlocked("REMOTE_SOURCE_TLS_VERIFY_FULL_REQUIRED")
    return values


class Postgres:
    def __init__(self, bin_dir: Path, env: dict[str, str] | None = None):
        self.bin_dir = bin_dir.resolve()
        supplied = dict(os.environ if env is None else env)
        # Never inherit alternate libpq routes, options, passwords or tracing.
        self.env = {k: v for k, v in supplied.items() if not k.upper().startswith("PG")}
        for key in ("PGSERVICEFILE", "PGPASSFILE"):
            if key in supplied:
                self.env[key] = supplied[key]
        self.env.update(PGCONNECT_TIMEOUT="10", PGAPPNAME="todo-recovery-bounded")
        self.versions: dict[str, int] = {}

    def command(self, tool: str, *args: str) -> list[str]:
        if tool not in {"psql", "pg_dump", "pg_restore"}:
            raise RecoveryBlocked("TOOL_NOT_ALLOWED")
        path = self.bin_dir / (tool + (".exe" if os.name == "nt" else ""))
        regular(path)
        return [str(path), *args]

    def run(self, tool: str, *args: str, readonly: bool = False, timeout: int = 120) -> str:
        env = dict(self.env)
        env["PGOPTIONS"] = "-c statement_timeout=120000 -c lock_timeout=10000"
        if readonly:
            env["PGOPTIONS"] += " -c default_transaction_read_only=on"
        try:
            result = subprocess.run(self.command(tool, *args), env=env, capture_output=True,
                                    text=True, encoding="utf-8", timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryBlocked("POSTGRES_EXECUTION_UNAVAILABLE") from None
        if result.returncode:
            # Never leak libpq stderr, DSNs, passwords, SQL or table contents.
            raise RecoveryBlocked("POSTGRES_COMMAND_FAILED")
        return result.stdout.strip()

    def major(self, tool: str) -> int:
        output = self.run(tool, "--version", timeout=10)
        match = re.search(r"\(PostgreSQL\) (\d+)\.", output)
        if not match:
            raise RecoveryBlocked("POSTGRES_TOOL_VERSION_INVALID")
        return int(match.group(1))

    def sql(self, alias: str, sql: str, *, snapshot: str | None = None) -> Any:
        prefix = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL timezone='UTC'; "
        if snapshot:
            if not re.fullmatch(r"[0-9A-Fa-f-]{1,80}", snapshot):
                raise RecoveryBlocked("SNAPSHOT_ID_INVALID")
            # SET TRANSACTION SNAPSHOT must precede any query; timezone is not a query.
            prefix += f"SET TRANSACTION SNAPSHOT '{snapshot}'; "
        output = self.run("psql", "-X", "-qAt", "--no-password", "-v", "ON_ERROR_STOP=1",
                          "-d", f"service={alias}", "-c", prefix + sql + "; COMMIT;", readonly=True)
        try:
            return json.loads(output)
        except (ValueError, TypeError):
            raise RecoveryBlocked("POSTGRES_RESPONSE_INVALID") from None

    @contextmanager
    def snapshot(self, alias: str) -> Iterator[str]:
        proc = subprocess.Popen(self.command("psql", "-X", "-qAt", "--no-password",
            "-v", "ON_ERROR_STOP=1", "-d", f"service={alias}"), env={**self.env,
            "PGOPTIONS": "-c default_transaction_read_only=on -c idle_in_transaction_session_timeout=180000"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8")
        try:
            assert proc.stdin and proc.stdout
            proc.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSELECT pg_export_snapshot();\n")
            proc.stdin.flush()
            messages: queue.Queue[str] = queue.Queue()
            reader = threading.Thread(target=lambda: messages.put(proc.stdout.readline()), daemon=True)
            reader.start()
            try:
                snapshot_id = messages.get(timeout=10).strip()
            except queue.Empty:
                raise RecoveryBlocked("SNAPSHOT_TIMEOUT") from None
            if not re.fullmatch(r"[0-9A-Fa-f-]{1,80}", snapshot_id):
                raise RecoveryBlocked("SNAPSHOT_ID_INVALID")
            yield snapshot_id
        finally:
            # Closing this one read-only connection rolls back its snapshot.
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)


def fingerprint(pg: Postgres, alias: str, snapshot: str | None = None) -> dict[str, Any]:
    names = pg.sql(alias, TABLES_SQL, snapshot=snapshot)
    if not isinstance(names, list) or len(names) > 128 or any(not isinstance(x, str) or not IDENT.fullmatch(x) for x in names):
        raise RecoveryBlocked("TABLE_SET_INVALID")
    result = {}
    for name in names:
        # Values never leave PostgreSQL: only sorted SHA-256 row digests are aggregated.
        query = f'''SELECT json_build_object('rows',count(*),'sha256',
encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h),''),'UTF8')),'hex'))
FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS h
FROM "todo_bus"."{name}" t) hashed'''
        result[name] = pg.sql(alias, query, snapshot=snapshot)
    return result


def validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise RecoveryBlocked("MANIFEST_INVALID")
    if type(value.get("source_major")) is not int or not 16 <= value["source_major"] <= 18:
        raise RecoveryBlocked("SOURCE_MAJOR_UNSUPPORTED")
    if not isinstance(value.get("archive_sha256"), str) or not SHA.fullmatch(value["archive_sha256"]):
        raise RecoveryBlocked("MANIFEST_INVALID")
    tables = value.get("tables")
    if not isinstance(tables, dict) or not REQUIRED <= tables.keys() or len(tables) > 128:
        raise RecoveryBlocked("REQUIRED_TABLES_MISSING")
    for name, item in tables.items():
        if not IDENT.fullmatch(name) or not isinstance(item, dict) or type(item.get("rows")) is not int or item["rows"] < 0:
            raise RecoveryBlocked("MANIFEST_INVALID")
        if not isinstance(item.get("sha256"), str) or not SHA.fullmatch(item["sha256"]):
            raise RecoveryBlocked("MANIFEST_INVALID")
    if sum(tables[x]["rows"] for x in REQUIRED) == 0:
        raise RecoveryBlocked("EMPTY_SOURCE_NOT_RECOVERY")
    return value


def bundle_manifest(bundle: Path) -> dict[str, Any]:
    for name in ("manifest.json", "database.dump"):
        regular(bundle / name)
    if (bundle / "manifest.json").stat().st_size > 131072:
        raise RecoveryBlocked("MANIFEST_TOO_LARGE")
    data = validate_manifest(json.loads((bundle / "manifest.json").read_text(encoding="utf-8")))
    if digest_file(bundle / "database.dump") != data["archive_sha256"]:
        raise RecoveryBlocked("ARCHIVE_DIGEST_MISMATCH")
    with (bundle / "database.dump").open("rb") as stream:
        if stream.read(5) != b"PGDMP":
            raise RecoveryBlocked("CUSTOM_ARCHIVE_REQUIRED")
    return data


@contextmanager
def exclusive(bundle: Path) -> Iterator[None]:
    if bundle.is_symlink():
        raise RecoveryBlocked("BUNDLE_SYMLINK_FORBIDDEN")
    bundle.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt" and (bundle.stat().st_mode & 0o077):
        raise RecoveryBlocked("BUNDLE_PERMISSIONS_UNSAFE")
    path = bundle / ".operation.lock"
    try:
        handle = path.open("x", encoding="ascii")
    except FileExistsError:
        raise RecoveryBlocked("RECOVERY_BUSY") from None
    try:
        handle.write(str(os.getpid()))
        handle.close()
        yield
    finally:
        path.unlink(missing_ok=True)


def write_json_new(path: Path, value: Any) -> None:
    # Refuse to replace an old receipt or follow a symlink.
    with path.open("xb") as handle:
        handle.write(canonical(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        path.chmod(0o600)


def capture(pg: Postgres, bundle: Path, correlation: str) -> dict[str, Any]:
    alias = "todo_recovery_source"
    source = service(alias, pg.env, target=False)
    with exclusive(bundle):
        if (bundle / "manifest.json").exists():
            value = bundle_manifest(bundle)
            if value.get("correlation_id") != correlation:
                raise RecoveryBlocked("CORRELATION_MISMATCH")
            return {"state": "already_captured", "archive_sha256": value["archive_sha256"], "cutover_ready": False}
        if (bundle / "database.dump").exists() or (bundle / "database.dump.part").exists():
            raise RecoveryBlocked("PARTIAL_BUNDLE_REQUIRES_REVIEW")
        identity = pg.sql(alias, IDENTITY_SQL)
        if identity["database"] != source["dbname"]:
            raise RecoveryBlocked("SOURCE_IDENTITY_MISMATCH")
        major = identity["major"]
        if major not in (16, 17, 18) or pg.major("pg_dump") < major:
            raise RecoveryBlocked("DUMP_CLIENT_TOO_OLD_OR_UNSUPPORTED")
        with pg.snapshot(alias) as snap:
            tables = fingerprint(pg, alias, snap)
            if not REQUIRED <= tables.keys():
                raise RecoveryBlocked("REQUIRED_TABLES_MISSING")
            pg.run("pg_dump", "--no-password", "--format=custom", "--no-owner", "--no-privileges",
                   "--schema=todo_bus", "--strict-names", f"--snapshot={snap}",
                   f"--file={bundle / 'database.dump.part'}", f"--dbname=service={alias}", readonly=True)
        partial = bundle / "database.dump.part"
        regular(partial)
        if os.name != "nt":
            partial.chmod(0o600)
        partial.rename(bundle / "database.dump")
        value = {"schema_version": 1, "correlation_id": correlation, "source_major": major,
                 "archive_sha256": digest_file(bundle / "database.dump"), "tables": tables,
                 "captured_at": datetime.now(timezone.utc).isoformat(), "cutover_ready": False}
        validate_manifest(value)
        write_json_new(bundle / "manifest.json", value)
        bundle_manifest(bundle)
        return {"state": "captured", "archive_sha256": value["archive_sha256"], "tables": len(tables), "cutover_ready": False}


def restore(pg: Postgres, bundle: Path, correlation: str) -> dict[str, Any]:
    alias = "todo_recovery_target"
    target = service(alias, pg.env, target=True)
    with exclusive(bundle):
        manifest = bundle_manifest(bundle)
        if manifest.get("correlation_id") != correlation:
            raise RecoveryBlocked("CORRELATION_MISMATCH")
        identity = pg.sql(alias, IDENTITY_SQL)
        if identity["database"] != target["dbname"]:
            raise RecoveryBlocked("TARGET_IDENTITY_MISMATCH")
        if identity["major"] < manifest["source_major"] or pg.major("pg_restore") < manifest["source_major"]:
            raise RecoveryBlocked("TARGET_OR_RESTORE_CLIENT_TOO_OLD")
        if identity.get("superuser") is not False:
            raise RecoveryBlocked("NON_SUPERUSER_RESTORE_REQUIRED")
        receipt_path = bundle / "restore-receipt.json"
        if receipt_path.exists():
            regular(receipt_path)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if receipt.get("archive_sha256") != manifest["archive_sha256"] or receipt.get("target_database") != target["dbname"]:
                raise RecoveryBlocked("RESTORE_RECEIPT_MISMATCH")
            if fingerprint(pg, alias) != manifest["tables"]:
                raise RecoveryBlocked("RESTORED_DATA_DRIFT")
            return {**receipt, "state": "already_verified", "restore_executed": False}
        occupied = pg.sql(alias, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f')")
        if occupied:
            raise RecoveryBlocked("TARGET_NOT_EMPTY")
        pg.run("pg_restore", "--no-password", "--single-transaction", "--exit-on-error", "--no-owner",
               "--no-privileges", f"--dbname=service={alias}", str(bundle / "database.dump"))
        observed = fingerprint(pg, alias)
        if observed != manifest["tables"]:
            raise RecoveryBlocked("RESTORED_DATA_MISMATCH")
        receipt = {"state": "verified", "archive_sha256": manifest["archive_sha256"],
                   "correlation_id": correlation, "target_database": target["dbname"],
                   "target_major": identity["major"], "tables_verified": len(observed),
                   "rows_verified": sum(item["rows"] for item in observed.values()),
                   "restore_executed": True, "cutover_ready": False, "workers_started": False}
        write_json_new(receipt_path, receipt)
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "verify-restore"))
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,96}", args.correlation_id):
            raise RecoveryBlocked("CORRELATION_INVALID")
        pg = Postgres(args.bin_dir)
        result = (capture if args.action == "capture" else restore)(pg, args.bundle, args.correlation_id)
    except RecoveryBlocked as error:
        result = {"state": "blocked", "reason": str(error), "cutover_ready": False}
    except Exception:
        result = {"state": "blocked", "reason": "RECOVERY_UNEXPECTED_FAILURE", "cutover_ready": False}
    print(json.dumps(result, sort_keys=True))
    return 2 if result["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
