#!/usr/bin/env python3
"""Inventario Risk1 fixo do publicador e ingress ReqSys DEV no Desktop.

Nao inicia, reinicia, publica, conecta ao DB, executa scripts instalados nem
le chaves DPAPI. Emite somente um recibo sanitizado, nao um aceite operacional.
A invocacao fisica depende de Session Launcher e Command Gateway ja admitidos.
"""
from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

HOST = "DESKTOP-PDQK954"
RUNNER = "DESKTOP-PDQK954-runtime"
REPO = "ericson-j-santos/desktop-pc24x7-runtime"
REQSYS = "ericson-j-santos/reqsys-v2-enterprise-real"
TASK = "ReqSys-Dev-Runtime-Supervisor"
TOPIC = "reqsys-dev-locator-1651e9182d6e1c939fa6672c1248c9d532716fe7"
PUBLIC_KEY = "Ox1kIxgrkNTG96NI69Obi/W+ZiZz2jxw3DLCQMvwMcM="
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
CORRELATION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{7,126}\Z")
MAX_FILE = 65536
ROOT_PUBLISHER = Path("RuntimeSupervisor/scripts/pc24x7_dev_locator_publisher.py")
ROOT_SUPERVISOR = Path("RuntimeSupervisor/scripts/pc24x7_dev_runtime_supervisor.py")
FILES = {
    "manifest": "RuntimeSupervisor/manifest.json",
    "public_identity": "RuntimeSupervisor/dev-locator-public.json",
    "tunnels": "PublicRuntime/dev-tunnels.json",
    "publication": "PublicRuntime/dev-locator-publish.json",
    "supervisor": "PublicRuntime/dev-supervisor.json",
}
ENDPOINTS = (
    "/api/health", "/api/runtime/health", "/api/runtime/readiness",
    "/api/runtime/build-info", "/@vite/client",
)
RECEIPT = Path("artifacts/reqsys-dev-locator-readonly/evidence.json")


class InventoryBlocked(ValueError):
    """Stable error only; never contains private paths or file content."""


def require(value: bool, code: str) -> None:
    if not value:
        raise InventoryBlocked(code)


def checked_path(path: Path) -> None:
    for node in (path, *path.parents):
        try:
            st = node.lstat()
        except FileNotFoundError:
            continue  # Missing is reported as missing, never resolved elsewhere.
        except OSError:
            raise InventoryBlocked("fixed_path_unavailable") from None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise InventoryBlocked("fixed_path_redirected")
        if node != path and not stat.S_ISDIR(st.st_mode):
            raise InventoryBlocked("fixed_parent_invalid")


def file_bytes(root: Path, relative: Path) -> bytes | None:
    require(relative.as_posix() in {*FILES.values(), ROOT_PUBLISHER.as_posix(),
                                   ROOT_SUPERVISOR.as_posix()}, "fixed_file_unapproved")
    path = root / relative
    checked_path(path)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE or before.st_nlink != 1:
            raise InventoryBlocked("fixed_file_invalid")
        with path.open("rb") as f:
            value = f.read(MAX_FILE + 1)
        after = path.stat()
    except FileNotFoundError:
        return None
    except (OSError, PermissionError):
        raise InventoryBlocked("fixed_file_unavailable") from None
    require(len(value) <= MAX_FILE and
            (before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), "fixed_file_changed")
    return value


def pairs_unique(items):
    result = {}
    for key, value in items:
        require(key not in result, "fixed_json_duplicate_key")
        result[key] = value
    return result


def reject_constant(_item):
    raise InventoryBlocked("fixed_json_nonfinite")


def read_json(root: Path, relative: str) -> tuple[dict | None, str | None]:
    data = file_bytes(root, Path(relative))
    if data is None:
        return None, None
    try:
        obj = json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs_unique,
                         parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise InventoryBlocked("fixed_json_invalid") from None
    require(type(obj) is dict, "fixed_json_invalid")
    return obj, hashlib.sha256(data).hexdigest()


def allowed_public_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 180:
        return False
    try:
        url = urlsplit(value)
    except (ValueError, TypeError):
        return False
    try:
        hostname, port = url.hostname, url.port
    except ValueError:
        return False
    return (url.scheme == "https" and isinstance(hostname, str)
            and hostname.endswith(".trycloudflare.com")
            and url.username is None and url.password is None and port is None
            and url.path in ("", "/") and not url.query and not url.fragment)


def file_summaries(root: Path, now: int, expected_publisher_sha256: str) -> dict:
    result: dict = {}
    for name, relative in FILES.items():
        obj, digest = read_json(root, relative)
        if obj is None:
            result[name] = {"present": False}
            continue
        item: dict = {"present": True, "sha256": digest}
        if name == "manifest":
            sha = obj.get("source_head")
            item["source_sha"] = sha if isinstance(sha, str) and SHA40.fullmatch(sha) else None
            item["contract_v2"] = obj.get("schema_version") == "2.0.0"
        elif name == "public_identity":
            item["pinned_public_identity"] = (obj.get("topic") == TOPIC
                                              and obj.get("public_key_b64") == PUBLIC_KEY)
        elif name == "tunnels":
            rows = obj.get("tunnels")
            require(type(rows) is list and len(rows) <= 16, "fixed_tunnels_invalid")
            item["tunnel_count"] = len(rows)
            item["url_format_valid_count"] = sum(
                allowed_public_url(x.get("url")) for x in rows if type(x) is dict)
            item["ready_flag_count"] = sum(
                x.get("ready") is True for x in rows if type(x) is dict)
            item["all_tunnel_items_objects"] = all(type(x) is dict for x in rows)
        elif name == "publication":
            value = obj.get("expires_at")
            item["published_flag"] = obj.get("published") is True
            item["publication_fresh_flag"] = type(value) is int and now < value <= now + 900
            count = obj.get("healthy_url_count")
            item["healthy_url_count_claimed"] = (count if type(count) is int and 0 <= count <= 16
                                                 else None)
            item["pinned_public_identity"] = (obj.get("topic") == TOPIC
                                              and obj.get("public_key_b64") == PUBLIC_KEY)
        elif name == "supervisor":
            item["contract_v2"] = obj.get("schema_version") == "2.0.0"
            item["ready_flag"] = obj.get("ready") is True
            item["local_runtime_contract_flag"] = obj.get("local_runtime_contract_ready") is True
            item["locator_ready_flag"] = obj.get("locator_ready") is True
            stamp = obj.get("timestamp_epoch")
            item["fresh_flag"] = type(stamp) is int and 0 <= now - stamp <= 900
        result[name] = item
    for label, relative in (("publisher_script", ROOT_PUBLISHER),
                            ("supervisor_script", ROOT_SUPERVISOR)):
        raw = file_bytes(root, relative)
        digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
        result[label] = {"present": raw is not None, "sha256": digest}
        if label == "publisher_script":
            result[label]["matches_reqsys_source"] = digest == expected_publisher_sha256
    return result


def task_xml_reader() -> bytes | None:
    try:
        done = subprocess.run(["schtasks.exe", "/Query", "/TN", TASK, "/XML"],
                              capture_output=True, check=False, timeout=6,
                              stdin=subprocess.DEVNULL, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode or len(done.stdout) > MAX_FILE:
        return None
    return done.stdout


def task_summary(raw: bytes | None) -> dict:
    if raw is None:
        return {"query_status": "unavailable_or_not_registered"}
    require(len(raw) <= MAX_FILE, "task_metadata_oversize")
    try:
        document = ET.fromstring(raw)
    except ET.ParseError:
        raise InventoryBlocked("task_xml_invalid") from None
    def find_last(tag: str) -> str | None:
        for element in document.iter():
            if element.tag.rsplit("}", 1)[-1] == tag:
                return element.text
        return None
    enabled = find_last("Enabled")
    return {"query_status": "observed", "task_enabled": enabled == "true",
            "interval_is_six_minutes": find_last("Interval") == "PT6M",
            "interactive_logon_type": find_last("LogonType") == "InteractiveToken",
            "xml_sha256": hashlib.sha256(raw).hexdigest()}


def local_request(path: str) -> tuple[int | None, bytes]:
    require(path in ENDPOINTS, "local_path_unapproved")
    connection = HTTPConnection("127.0.0.1", 8083, timeout=3)
    try:
        connection.request("GET", path, headers={"Accept": "application/json",
                                                 "Cache-Control": "no-store"})
        response = connection.getresponse()
        data = response.read(8193)
        if len(data) > 8192:
            return None, b""
        return response.status, data
    except (OSError, HTTPException, TimeoutError):
        return None, b""
    finally:
        connection.close()


def http_summary(request, expected_reqsys_sha: str) -> dict:
    result = {}
    for path in ENDPOINTS:
        status, raw = request(path)
        require(status is None or type(status) is int and 100 <= status <= 599,
                "local_status_invalid")
        require(type(raw) is bytes and len(raw) <= 8192, "local_body_invalid")
        item = {"http_status": status}
        if path == "/api/runtime/build-info" and status == 200:
            try:
                payload = json.loads(raw.decode("utf-8"))
                if type(payload) is dict:
                    data = payload.get("data", payload)
                    sha = data.get("build_sha") if type(data) is dict else None
                    sha = sha if isinstance(sha, str) and SHA40.fullmatch(sha) else None
                else:
                    sha = None
            except (UnicodeError, ValueError, RecursionError):
                sha = None
            item["observed_build_sha"] = sha
            item["build_sha_matches_reqsys_main"] = sha == expected_reqsys_sha
        result[path] = item
    return result


def collect(root: Path, *, now: int, source_sha: str, expected_reqsys_sha: str,
            expected_publisher_sha256: str, correlation_id: str,
            task_reader=task_xml_reader, request=local_request) -> dict:
    for value, matcher in ((source_sha, SHA40), (expected_reqsys_sha, SHA40),
                           (expected_publisher_sha256, SHA64), (correlation_id, CORRELATION)):
        require(isinstance(value, str) and matcher.fullmatch(value) is not None,
                "inventory_identity_invalid")
    require(isinstance(root, Path) and root.is_absolute() and type(now) is int,
            "inventory_root_invalid")
    checked_path(root)
    files = file_summaries(root, now, expected_publisher_sha256)
    scheduled = task_summary(task_reader())
    endpoints = http_summary(request, expected_reqsys_sha)
    problems = []
    if files["publisher_script"]["matches_reqsys_source"] is not True:
        problems.append("installed_publisher_not_current")
    if not files["public_identity"].get("pinned_public_identity"):
        problems.append("public_identity_unverified")
    if scheduled.get("task_enabled") is not True:
        problems.append("publisher_schedule_not_enabled")
    if files["tunnels"].get("url_format_valid_count", 0) < 1:
        problems.append("ingress_url_absent_or_invalid")
    if not files["publication"].get("published_flag") or not files["publication"].get("publication_fresh_flag"):
        problems.append("publication_unverified_or_expired")
    if not all(endpoints[route]["http_status"] == 200 for route in ENDPOINTS[:4]):
        problems.append("local_runtime_contract_unavailable")
    if endpoints["/@vite/client"]["http_status"] != 404:
        problems.append("static_frontend_negative_unverified")
    if endpoints["/api/runtime/build-info"].get("build_sha_matches_reqsys_main") is not True:
        problems.append("reqsys_dev_build_sha_unverified")
    return {
        "schema_version": "1.0.0", "result": "LOCATOR_RISK1_INVENTORY_OBSERVED",
        "host": HOST, "runner": RUNNER, "repository": REPO,
        "expected_source_sha": source_sha, "expected_reqsys_main_sha": expected_reqsys_sha,
        "correlation_id": correlation_id, "observation_epoch": now,
        "files": files, "scheduled_publisher": scheduled,
        "local_http": endpoints, "blockers": problems,
        "read_only": True, "external_ntfy_checked": False,
        "locator_signature_independently_verified": False,
        "publisher_process_identity_verified": False,
        "runtime_deployed_or_modified": False, "secrets_read_or_emitted": False,
        "ready_for_dev": False, "ready_for_pr": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventario Risk1 de locator ReqSys DEV")
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-reqsys-sha", required=True)
    parser.add_argument("--expected-publisher-sha256", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    require(os.name == "nt" and env.get("COMPUTERNAME", "").upper() == HOST
            and env.get("RUNNER_NAME") == RUNNER and env.get("GITHUB_REPOSITORY") == REPO
            and env.get("GITHUB_SHA") == args.expected_head,
            "physical_source_identity_unverified")
    local = env.get("LOCALAPPDATA", "")
    require(bool(local) and Path(local).is_absolute(), "localappdata_unavailable")
    report = collect(
        Path(local) / "ReqSys", now=int(time.time()), source_sha=args.expected_head,
        expected_reqsys_sha=args.expected_reqsys_sha,
        expected_publisher_sha256=args.expected_publisher_sha256,
        correlation_id=args.correlation_id,
    )
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
                       encoding="utf-8")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryBlocked as error:
        print(json.dumps({"result": "LOCATOR_RISK1_INVENTORY_BLOCKED", "reason": str(error),
                          "read_only": True, "ready_for_dev": False}))
        raise SystemExit(2) from None
