"""Bounded read-only qualification before Orchestrator runner activation."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = "2232022f310970df54299263f0ea93f48ee2a56a"


def failure_kind(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").casefold()
    if any(item in text for item in ("access is denied", "access denied", "acesso negado")):
        return "access_denied"
    if any(item in text for item in ("cannot find", "not exist", "não pode encontrar", "nao pode encontrar", "não existe")):
        return "not_found"
    if "rpc" in text:
        return "rpc_unavailable"
    return "unclassified"


def bounded_json(path: Path, preflight) -> dict:
    preflight.checked_path(path, directory=False)
    raw = path.read_bytes()
    if len(raw) > 262144:
        raise ValueError("bounded_file")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("invalid_json")
    return payload


def task_probe(leaf: str) -> dict:
    task = r"\Automation" + "\\" + leaf
    cp = subprocess.run(["schtasks.exe", "/Query", "/TN", task, "/XML"],
                        capture_output=True, timeout=15, check=False)
    report = {"query_exit": cp.returncode, "query_status": "observed" if cp.returncode == 0 else failure_kind(cp.stderr)}
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    path = Path(os.environ["SystemRoot"]) / "System32" / "Tasks" / "Automation" / leaf
    ctypes.set_last_error(0)
    attributes = kernel.GetFileAttributesW(str(path))
    report["fixed_task_file_attributes_observed"] = attributes != 0xFFFFFFFF
    report["fixed_task_file_error"] = ctypes.get_last_error() if attributes == 0xFFFFFFFF else 0
    return report


def main() -> int:
    result = {"kind": "orchestrator-activation-inventory", "source_sha": SOURCE,
              "read_only": True, "registration_performed": False, "runner_started": False, "tasks_changed": False}
    try:
        source = Path(os.environ["APPROVED_SOURCE_ROOT"]).resolve()
        source.relative_to(Path(r"C:\dev\chatgpt-workers").resolve())
        sys.path.insert(0, str(source / "scripts"))
        bootstrap = importlib.import_module("bootstrap_dedicated_runtime_runner")
        preflight = importlib.import_module("orchestrator_dev_runner_preflight")
        watchdog = importlib.import_module("desktop_control_plane_watchdog")
        preflight.require_source(SOURCE)
        if bootstrap.validate_host().casefold() != "desktop-pdqk954":
            raise ValueError("host")
        binding = preflight.preflight(expected_sha=SOURCE, correlation_id="orchestrator-activation-inventory-21", local_auth_only=True)
        if binding.get("observed_runner_id") != 21 or binding.get("registration_required") is not False:
            raise ValueError("runner_binding")
        result["runner_id"] = 21
        result["registered_binding_validated"] = True
        result["process_elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        result["tasks"] = {leaf: task_probe(leaf) for leaf in (
            "DesktopPc24x7RuntimeWatchdog", "DesktopPc24x7RuntimeHealthSupervisor", "DesktopPc24x7AdminBroker")}
        schedule = subprocess.run(["sc.exe", "query", "Schedule"], capture_output=True, timeout=15, check=False)
        result["task_scheduler_running"] = schedule.returncode == 0 and b"RUNNING" in schedule.stdout
        base = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7"
        for directory, key in (("ControlPlaneWatchdog", "watchdog"), ("AdminBroker", "broker")):
            section = {"metadata_status": "unavailable", "install_evidence_status": "unavailable", "heartbeat_fresh_90s": None}
            root = base / directory
            try:
                metadata = bounded_json(root / "metadata.json", preflight)
                section.update(metadata_status="observed", source_sha=(metadata.get("source_sha") if isinstance(metadata.get("source_sha"), str) and re.fullmatch(r"[0-9a-f]{40}", metadata["source_sha"]) else None),
                               metadata_host_matches=str(metadata.get("host") or "").casefold() == "desktop-pdqk954")
                for field in ("activation_pending", "requires_uac_activation", "admin_channel_ready"):
                    value = metadata.get(field)
                    section[field] = value if type(value) is bool else None
            except Exception:
                pass
            try:
                installed = bounded_json(root / "install-evidence.json", preflight)
                section["install_evidence_status"] = "observed"
                section["installation"] = {k: (installed.get(k) if type(installed.get(k)) is bool else None) for k in (
                    "ok", "activation_pending", "requires_uac_activation", "headless_boot_ready")}
            except Exception:
                pass
            if key == "broker":
                try:
                    heartbeat = bounded_json(root / "broker-heartbeat.json", preflight)
                    stamp = datetime.fromisoformat(str(heartbeat["updated_at"]).replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - stamp).total_seconds()
                    section["heartbeat_fresh_90s"] = 0 <= age <= 90
                except Exception:
                    pass
            result[key] = section
        result["ok"] = True
    except Exception:
        result.update(ok=False, state="activation_inventory_blocked")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
