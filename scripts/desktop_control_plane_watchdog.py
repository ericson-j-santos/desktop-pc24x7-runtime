#!/usr/bin/env python3
"""Supervisor autônomo do plano de controle local do Desktop PC24x7.

Objetivo:
- recuperar RDC e GitHub Actions runner sem depender de nenhum dos dois;
- iniciar no boot via tarefa Windows S4U;
- manter evidência local sanitizada;
- não ler nem registrar segredos do runner/RDC;
- operar somente em DESKTOP-PDQK954 e local/DEV.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import locale
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pc24x7_host_policy import authorized_host

EXPECTED_HOST = "DESKTOP-PDQK954"  # compatibility default; authorization is host-policy driven
SERVICE_NAME = "desktop-pc24x7-runtime-watchdog"
TASK_FOLDER = r"\Automation"
TASK_LEAF = "DesktopPc24x7RuntimeWatchdog"
TASK_NAME = TASK_FOLDER + "\\" + TASK_LEAF
TASK_TRIGGER_BOOT = 8
TASK_ACTION_EXEC = 0
TASK_LOGON_S4U = 2
TASK_CREATE_OR_UPDATE = 6
TASK_RUNLEVEL_LUA = 0
TASK_INSTANCES_IGNORE_NEW = 2
CONFIRM = "INSTALL-DESKTOP-PC24X7-RUNTIME-WATCHDOG"

RDC_RECOVERY_CONFIRM = "RECOVER-GOVERNED-RDC"
RDC_RECOVERY_SCRIPT = "pc24x7_rdc_recovery.py"
UAC_LAUNCHER_SCRIPT = "desktop_control_plane_watchdog_uac_launcher.py"
HOST_POLICY_SCRIPT = "pc24x7_host_policy.py"
RDC_HEADLESS_CLAIM = Path(r"C:\ProgramData\ReqSys\RdcSvc\rdc-headless-owner.json")
RDC_CLAIM_MAX_AGE_SECONDS = 20.0

RUNNER_PROCESS = "Runner.Listener.exe"
RUNNER_REQUIRED = ((".runner",), ("run.cmd",), ("bin", "Runner.Listener.exe"))
MIN_SUPPORTED_RUNNER_VERSION = "2.337.0"
MIN_SUPPORTED_RUNNER_VERSION_PARTS = (2, 337, 0)
DEFAULT_WATCH_SECONDS = 30
RUNNER_START_TIMEOUT_SECONDS = 30
RDC_RECOVERY_TIMEOUT_SECONDS = 60


class WatchdogError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def authorized_desktop_profile(host: str):
    try:
        profile = authorized_host(host)
    except ValueError as exc:
        raise WatchdogError(str(exc)) from None
    if profile.role not in {"desktop-primary", "desktop-secondary"}:
        raise WatchdogError(f"host não autorizado para watchdog desktop: {host}")
    return profile


def require_windows_desktop() -> str:
    if os.name != "nt":
        raise WatchdogError("Windows obrigatório")
    host = socket.gethostname()
    authorized_desktop_profile(host)
    return host


def default_runtime_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise WatchdogError("LOCALAPPDATA não definido")
    return Path(local) / "DesktopPC24x7" / "ControlPlaneWatchdog"


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _candidate_runner_homes() -> list[Path]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    return [Path(local) / "DesktopPC24x7" / "GitHubRunner"]


def validate_runner_home(path: Path) -> Path:
    resolved = path.resolve()
    missing = ["/".join(parts) for parts in RUNNER_REQUIRED if not resolved.joinpath(*parts).is_file()]
    if missing:
        raise WatchdogError("runner_home inválido; arquivos ausentes: " + ", ".join(missing))
    return resolved


def _parse_runner_version(value: str) -> tuple[int, int, int]:
    raw = str(value or "").strip()
    parts = raw.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise WatchdogError("runner_version_invalid")
    return tuple(int(part) for part in parts)


def inspect_runner_version(runner_home: Path) -> dict[str, Any]:
    root = validate_runner_home(runner_home)
    listener = root / "bin" / RUNNER_PROCESS
    completed = subprocess.run(
        [str(listener), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise WatchdogError(f"runner_version_unreadable:exit={completed.returncode}")
    observed = completed.stdout.strip()
    observed_parts = _parse_runner_version(observed)
    if observed_parts < MIN_SUPPORTED_RUNNER_VERSION_PARTS:
        raise WatchdogError(
            "runner_version_unsupported:"
            f"{observed}:minimum={MIN_SUPPORTED_RUNNER_VERSION}"
        )
    return {
        "runner_version": observed,
        "minimum_supported_runner_version": MIN_SUPPORTED_RUNNER_VERSION,
        "runner_version_supported": True,
    }


def discover_runner_home(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return validate_runner_home(explicit)
    seen: set[str] = set()
    for candidate in _candidate_runner_homes():
        key = os.path.normcase(str(candidate))
        if key in seen:
            continue
        seen.add(key)
        try:
            return validate_runner_home(candidate)
        except (WatchdogError, OSError):
            continue
    raise WatchdogError(
        "GitHub Actions runner não localizado; informe --runner-home uma única vez na instalação"
    )


def _runner_process_ids() -> list[int]:
    if os.name != "nt":
        return []

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == wintypes.HANDLE(-1).value:
        raise WatchdogError(
            f"snapshot de processos falhou: winerror={ctypes.get_last_error()}"
        )
    pids: list[int] = []
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(ProcessEntry32W)
        if not process_first(snapshot, ctypes.byref(entry)):
            error = ctypes.get_last_error()
            if error == 18:  # ERROR_NO_MORE_FILES
                return []
            raise WatchdogError(f"enumeração de processos falhou: winerror={error}")
        while True:
            if entry.szExeFile.casefold() == RUNNER_PROCESS.casefold():
                pids.append(int(entry.th32ProcessID))
            if not process_next(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error not in (0, 18):  # ERROR_NO_MORE_FILES
                    raise WatchdogError(
                        f"enumeração de processos falhou: winerror={error}"
                    )
                break
        return pids
    finally:
        close_handle(snapshot)


def _process_executable_path(pid: int) -> Path | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_path = kernel32.QueryFullProcessImageNameW
    query_path.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_path.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query_path(handle, 0, buffer, ctypes.byref(size)):
            return None
        return Path(buffer.value).resolve()
    finally:
        close_handle(handle)


def runner_process_snapshot(runner_home: Path) -> dict[str, Any]:
    runner_home = validate_runner_home(runner_home)
    expected = (runner_home / "bin" / RUNNER_PROCESS).resolve()
    matching: list[int] = []
    unresolved: list[int] = []
    observed: list[dict[str, Any]] = []
    for pid in _runner_process_ids():
        executable = _process_executable_path(pid)
        if executable is None:
            unresolved.append(pid)
            continue
        observed.append({"pid": pid, "path": str(executable)})
        if os.path.normcase(str(executable)) == os.path.normcase(str(expected)):
            matching.append(pid)

    if len(matching) > 1:
        raise WatchdogError("mais de um listener pertence ao runner governado")
    if not matching and unresolved:
        raise WatchdogError("runner_listener_identity_unverifiable")
    return {
        "expected_executable": str(expected),
        "matching_pids": matching,
        "unresolved_pids": unresolved,
        "observed": observed,
    }


def runner_running(runner_home: Path | None = None) -> bool:
    if os.name != "nt":
        return False
    if runner_home is None:
        return bool(_runner_process_ids())
    return bool(runner_process_snapshot(runner_home)["matching_pids"])


def _creationflags() -> int:
    if os.name != "nt":
        return 0
    return (
        subprocess.CREATE_NEW_PROCESS_GROUP
        | subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NO_WINDOW
    )



ORCHESTRATOR_RUNNER_ID = 21
ORCHESTRATOR_ENV_KEYS = {
    "systemroot", "windir", "comspec", "path", "pathext", "os",
    "username", "userdomain", "computername", "userprofile", "appdata", "localappdata",
    "homedrive", "homepath", "temp", "tmp", "processor_architecture",
    "processor_identifier", "number_of_processors", "programfiles", "programfiles(x86)",
    "programw6432", "programdata", "allusersprofile", "public",
}


def orchestrator_runner_environment(environment: dict[str, str]) -> dict[str, str]:
    """Give the new listener only fixed Windows runtime variables."""
    return {key: value for key, value in environment.items()
            if key.casefold() in ORCHESTRATOR_ENV_KEYS}


def _is_orchestrator_runner_home(home: Path) -> bool:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return False
    expected = Path(local) / "EngineeringOrchestratorDEV" / "GitHubRunner"
    return os.path.normcase(str(home.resolve())) == os.path.normcase(str(expected.resolve()))


def additional_orchestrator_runner_home(metadata: dict[str, Any]) -> Path | None:
    """Admit only the already registered fixed DEV profile, never arbitrary homes."""
    profiles = metadata.get("additional_runner_profiles", [])
    if profiles == []:
        return None
    if profiles != ["orchestrator-dev"]:
        raise WatchdogError("additional_runner_profile_rejected")
    from pc24x7_host_policy import ORCHESTRATOR_DEV_RUNNER_PROFILE as profile
    if socket.gethostname().casefold() != profile["host"].casefold():
        raise WatchdogError("additional_runner_host_rejected")
    local = Path(os.environ.get("LOCALAPPDATA") or "")
    if not local.is_absolute():
        raise WatchdogError("additional_runner_path_rejected")
    home = local / profile["directory"] / "GitHubRunner"
    _inventory_path(home, directory=True)
    data, _ = _inventory_json(home / ".runner")
    urls = [data[key] for key in ("repoUrl", "gitHubUrl") if key in data]
    names = [data[key] for key in ("agentName", "runnerName") if key in data]
    if (type(data.get("agentId")) is not int or data["agentId"] != ORCHESTRATOR_RUNNER_ID
        or not urls or any(not isinstance(url, str) or url.rstrip("/") !=
                             "https://github.com/" + profile["repository"] for url in urls)
        or not names or any(name != profile["runner_name"] for name in names)):
        raise WatchdogError("additional_runner_binding_rejected")
    return validate_runner_home(home)

def start_runner(runner_home: Path, log_path: Path) -> dict[str, Any]:
    runner_home = validate_runner_home(runner_home)
    version_info = inspect_runner_version(runner_home)
    try:
        snapshot = runner_process_snapshot(runner_home)
    except WatchdogError as exc:
        if str(exc) != "runner_listener_identity_unverifiable":
            raise
        # Outro listener pode estar protegido/elevado e, portanto, sem caminho
        # consultável nesta sessão. Não o encerramos nem presumimos que pertença
        # ao runner governado; tentamos somente iniciar o contrato local exato.
        snapshot = {"matching_pids": [], "unresolved_pids": _runner_process_ids()}
    if snapshot["matching_pids"]:
        return {
            "status": "process_running",
            "started": False,
            "listener_pid": snapshot["matching_pids"][0],
            "github_connectivity_verified": False,
            "pickup_required": True,
            **version_info,
        }

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    cmd = system_root / "System32" / "cmd.exe"
    run_cmd = runner_home / "run.cmd"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("a", encoding="utf-8", buffering=1)
    child_env = (orchestrator_runner_environment(dict(os.environ))
                 if _is_orchestrator_runner_home(runner_home) else os.environ.copy())
    # GitHub Actions mata no cleanup processos que herdaram RUNNER_TRACKING_ID.
    # O listener é um serviço persistente do host, não um processo do job.
    child_env.pop("RUNNER_TRACKING_ID", None)
    # Credenciais temporárias do instalador/job não pertencem ao listener.
    child_env.pop("GH_TOKEN", None)
    child_env.pop("GITHUB_TOKEN", None)
    try:
        process = subprocess.Popen(
            [str(cmd), "/d", "/s", "/c", str(run_cmd)],
            cwd=str(runner_home),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            close_fds=True,
            creationflags=_creationflags(),
            env=child_env,
        )
    finally:
        log_handle.close()

    deadline = time.monotonic() + RUNNER_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        current = runner_process_snapshot(runner_home)
        if current["matching_pids"]:
            return {
                "status": "recovered",
                "started": True,
                "launcher_pid": process.pid,
                "listener_pid": current["matching_pids"][0],
                "github_connectivity_verified": False,
                "pickup_required": True,
                **version_info,
            }
        if process.poll() is not None:
            raise WatchdogError(f"runner terminou durante startup: exit={process.returncode}")
        time.sleep(1)

    raise WatchdogError("timeout aguardando Runner.Listener.exe do runner governado")


def _taskkill_runner(pid: int) -> subprocess.CompletedProcess[str]:
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    taskkill = system_root / "System32" / "taskkill.exe"
    return subprocess.run(
        [str(taskkill), "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False) or "utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )


def stop_runner(runner_home: Path) -> dict[str, Any]:
    runner_home = validate_runner_home(runner_home)
    snapshot = runner_process_snapshot(runner_home)
    matching = snapshot["matching_pids"]
    previous_pid: int | None = matching[0] if matching else None

    if previous_pid is not None:
        stopped = _taskkill_runner(previous_pid)
        if stopped.returncode != 0 and runner_running(runner_home):
            raise WatchdogError(f"listener governado não pôde ser encerrado: exit={stopped.returncode}")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and runner_running(runner_home):
            time.sleep(0.5)
        if runner_running(runner_home):
            raise WatchdogError("timeout encerrando listener governado")

    return {
        "stopped": previous_pid is not None,
        "previous_listener_pid": previous_pid,
        "termination_scope": "exact_runner_home",
    }


def restart_runner(runner_home: Path, log_path: Path) -> dict[str, Any]:
    stopped = stop_runner(runner_home)
    result = start_runner(runner_home, log_path)
    return {
        **result,
        "restart_requested": True,
        "previous_listener_pid": stopped["previous_listener_pid"],
        "termination_scope": stopped["termination_scope"],
        "github_connectivity_verified": False,
        "pickup_required": True,
    }


def read_rdc_claim() -> dict[str, Any]:
    if not RDC_HEADLESS_CLAIM.is_file():
        return {"fresh": False, "reason": "claim_missing"}
    try:
        payload = json.loads(RDC_HEADLESS_CLAIM.read_text(encoding="utf-8"))
        if payload.get("ready") is not True:
            return {"fresh": False, "reason": "claim_not_ready"}
        raw_updated = str(payload.get("updated_at") or "")
        updated = datetime.fromisoformat(raw_updated.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            raise ValueError("updated_at sem timezone")
        age = (datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()
        fresh = 0 <= age <= RDC_CLAIM_MAX_AGE_SECONDS
        return {
            "fresh": fresh,
            "reason": "fresh" if fresh else "claim_stale",
            "age_seconds": round(age, 3),
            "ready": True,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"fresh": False, "reason": "claim_invalid", "error_type": type(exc).__name__}


def recover_rdc(*, python_executable: Path, recovery_script: Path, evidence_path: Path) -> dict[str, Any]:
    claim = read_rdc_claim()
    if claim.get("fresh"):
        return {"status": "healthy", "recovered": False, "claim": claim}

    correlation_id = f"desktop-watchdog-rdc-{int(time.time())}"
    completed = subprocess.run(
        [
            str(python_executable),
            str(recovery_script),
            "--confirm",
            RDC_RECOVERY_CONFIRM,
            "--correlation-id",
            correlation_id,
            "--evidence-file",
            str(evidence_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=RDC_RECOVERY_TIMEOUT_SECONDS,
        check=False,
    )
    evidence: dict[str, Any] = {}
    if evidence_path.is_file():
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            evidence = {}
    if completed.returncode != 0 or evidence.get("ok") is not True:
        raise WatchdogError(
            "recuperação RDC falhou: "
            + str(evidence.get("error") or completed.stderr or completed.stdout)[-500:]
        )
    return {
        "status": "recovered",
        "recovered": True,
        "mode": evidence.get("mode"),
        "owner": evidence.get("owner"),
        "fallback_armed": bool(evidence.get("fallback_armed")),
    }


def _component_failure(component: str, exc: Exception) -> dict[str, Any]:
    message = str(exc)
    known_runner_codes = {
        "runner_version_invalid",
        "runner_version_unreadable",
        "runner_version_unsupported",
    }
    prefix = message.split(":", 1)[0]
    return {
        "status": "failed",
        "component": component,
        "error_code": prefix if prefix in known_runner_codes else type(exc).__name__,
        "recovered": False,
    }


def cycle(metadata: dict[str, Any]) -> dict[str, Any]:
    host = require_windows_desktop()
    runtime_root = Path(metadata["runtime_root"])
    release_root = Path(metadata["release_root"])
    runner_home = validate_runner_home(Path(metadata["runner_home"]))
    python_executable = Path(metadata["python_executable"])
    recovery_script = release_root / "scripts" / RDC_RECOVERY_SCRIPT
    additional_home = additional_orchestrator_runner_home(metadata)
    rdc_enabled = metadata.get("rdc_recovery_enabled", True)
    if type(rdc_enabled) is not bool:
        raise WatchdogError("rdc_recovery_policy_invalid")

    # Runner recovery is the primary control-plane dependency and must not be
    # blocked by an unrelated RDC failure. Each component is recovered and
    # evidenced independently.
    try:
        runner = start_runner(
            runner_home,
            runtime_root / "logs" / "github-runner.log",
        )
    except Exception as exc:
        runner = _component_failure("github_runner", exc)

    additional = {}
    if additional_home is not None:
        try:
            observed = start_runner(additional_home, runtime_root / "logs" / "orchestrator-dev-runner.log")
        except Exception as exc:
            observed = _component_failure("orchestrator_dev_runner", exc)
        additional["orchestrator-dev"] = {"runner_id": ORCHESTRATOR_RUNNER_ID, **observed}
    rdc_required = rdc_enabled and authorized_desktop_profile(host).role == "desktop-primary"
    if not rdc_required:
        rdc = {"status": "not_applicable", "reason": "disabled_by_owner" if not rdc_enabled else "legacy_rdc_primary_only"}
    elif recovery_script.is_file():
        try:
            rdc = recover_rdc(
                python_executable=python_executable,
                recovery_script=recovery_script,
                evidence_path=runtime_root / "evidence" / "rdc-recovery-last.json",
            )
        except Exception as exc:
            rdc = _component_failure("rdc", exc)
    else:
        rdc = {
            "status": "failed",
            "component": "rdc",
            "error_code": "rdc_recovery_script_missing",
            "recovered": False,
        }

    primary_runner_ok = runner.get("status") in {"recovered", "process_running"}
    additional_ok = all(item.get("status") in {"recovered", "process_running"} for item in additional.values())
    runner_ok = primary_runner_ok and additional_ok
    rdc_ok = not rdc_required or rdc.get("status") in {"healthy", "recovered"}
    payload = {
        "schema_version": "2",
        "service": SERVICE_NAME,
        "host": host,
        "source_sha": metadata["source_sha"],
        "generated_at": now_iso(),
        "rdc": rdc,
        "github_runner": runner,
        "runner_recovery_ok": runner_ok,
        "primary_runner_recovery_ok": primary_runner_ok,
        "additional_runners": additional,
        "additional_runner_recovery_ok": additional_ok,
        "rdc_recovery_enabled": rdc_enabled,
        "rdc_recovery_ok": rdc_ok,
        "rdc_required": rdc_required,
        "ok": runner_ok and rdc_ok,
        "partial": runner_ok != rdc_ok,
        "github_pickup_required": runner_ok,
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
    }
    atomic_json(runtime_root / "state.json", payload)
    return payload


def _acquire_watch_lock(runtime_root: Path):
    path = runtime_root / "watchdog.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    if os.name == "nt":
        import msvcrt
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            handle.close()
            raise WatchdogError("outro watchdog já está ativo") from exc
    return handle


def wait_watchdog_lock_released(
    runtime_root: Path, *, timeout_seconds: int = 15
) -> dict[str, Any]:
    deadline = time.monotonic() + max(1, min(timeout_seconds, 30))
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            handle = _acquire_watch_lock(runtime_root)
        except WatchdogError as exc:
            if str(exc) != "outro watchdog já está ativo":
                raise
            time.sleep(0.25)
            continue
        handle.close()
        return {"released": True, "attempts": attempts}
    raise WatchdogError("watchdog.lock permaneceu ocupado após Stop")


def watch(metadata_path: Path) -> int:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    runtime_root = Path(metadata["runtime_root"])
    interval = max(10, int(metadata.get("watch_interval_seconds") or DEFAULT_WATCH_SECONDS))
    lock_handle = _acquire_watch_lock(runtime_root)
    try:
        while True:
            try:
                cycle(metadata)
            except Exception as exc:
                atomic_json(
                    runtime_root / "state.json",
                    {
                        "schema_version": "1",
                        "service": SERVICE_NAME,
                        "host": socket.gethostname(),
                        "source_sha": metadata.get("source_sha"),
                        "generated_at": now_iso(),
                        "ok": False,
                        "error": str(exc)[:1000],
                        "error_type": type(exc).__name__,
                        "production_touched": False,
                        "secrets_read": False,
                        "reboot_performed": False,
                    },
                )
            time.sleep(interval)
    finally:
        lock_handle.close()


def _copy_release(source_root: Path, release_root: Path) -> None:
    scripts = release_root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(__file__).resolve(), scripts / Path(__file__).name)
    for required_name in (RDC_RECOVERY_SCRIPT, UAC_LAUNCHER_SCRIPT, HOST_POLICY_SCRIPT):
        required = source_root / "scripts" / required_name
        if not required.is_file():
            raise WatchdogError(f"script obrigatório ausente: {required}")
        shutil.copy2(required, scripts / required_name)


def launcher_bytes() -> bytes:
    return (
        "from pathlib import Path\n"
        "import json, runpy, sys\n"
        "metadata = Path(__file__).with_name('metadata.json')\n"
        "payload = json.loads(metadata.read_text(encoding='utf-8'))\n"
        "script = Path(payload['release_root']) / 'scripts' / 'desktop_control_plane_watchdog.py'\n"
        "script_dir = script.parent\n"
        "if str(script_dir) not in sys.path:\n"
        "    sys.path.insert(0, str(script_dir))\n"
        "sys.argv = [str(script), 'watch', '--metadata', str(metadata)]\n"
        "runpy.run_path(str(script), run_name='__main__')\n"
    ).encode("utf-8")


def _write_launcher(runtime_root: Path) -> Path:
    launcher = runtime_root / "run.py"
    launcher.write_bytes(launcher_bytes())
    return launcher


def load_installed_metadata(
    metadata_path: Path,
    *,
    require_current_release: bool = False,
) -> dict[str, Any]:
    metadata_path = metadata_path.resolve()
    if not metadata_path.is_file():
        raise WatchdogError("metadata do watchdog ausente")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    runtime_root = Path(str(metadata.get("runtime_root") or "")).resolve()
    release_root = Path(str(metadata.get("release_root") or "")).resolve()
    python_executable = Path(str(metadata.get("python_executable") or "")).resolve()
    source_sha = str(metadata.get("source_sha") or "")
    if metadata_path != runtime_root / "metadata.json":
        raise WatchdogError("metadata fora do runtime governado")
    if len(source_sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in source_sha):
        raise WatchdogError("source_sha da instalação inválido")
    expected_release = runtime_root / "releases" / source_sha.lower()
    if release_root != expected_release:
        raise WatchdogError("release_root não corresponde ao source_sha governado")
    metadata_host = str(metadata.get("host") or "").strip()
    authorized_desktop_profile(metadata_host)
    if os.name == "nt" and metadata_host.casefold() != socket.gethostname().casefold():
        raise WatchdogError("metadata pertence a outro host autorizado")
    if os.name == "nt" and runtime_root != default_runtime_root().resolve():
        raise WatchdogError("runtime_root fora do caminho governado do Desktop")
    release_watchdog = release_root / "scripts" / "desktop_control_plane_watchdog.py"
    launcher = runtime_root / "run.py"
    for path, label in (
        (release_watchdog, "watchdog instalado"),
        (python_executable, "Python instalado"),
        (launcher, "launcher estável"),
    ):
        if not path.is_file():
            raise WatchdogError(f"{label} ausente: {path}")
    if require_current_release and release_watchdog.resolve() != Path(__file__).resolve():
        raise WatchdogError("subcomando elevado deve executar da release imutável instalada")
    return {
        "metadata": metadata,
        "metadata_path": metadata_path,
        "runtime_root": runtime_root,
        "release_root": release_root,
        "release_watchdog": release_watchdog,
        "python_executable": python_executable,
        "launcher": launcher,
        "source_sha": source_sha.lower(),
    }


def _task_file_path() -> Path:
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    return system_root / "System32" / "Tasks" / TASK_FOLDER.lstrip("\\") / TASK_LEAF


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.normcase(str(left.resolve())) == os.path.normcase(
            str(right.resolve())
        )


def _validate_orphan_task_xml(
    payload: bytes,
    *,
    python_executable: Path,
    launcher: Path,
) -> None:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise WatchdogError("orphan_task_xml_invalid") from exc
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    uri = root.findtext(".//t:RegistrationInfo/t:URI", default="", namespaces=ns)
    logon_type = root.findtext(".//t:Principal/t:LogonType", default="", namespaces=ns)
    command = root.findtext(".//t:Actions/t:Exec/t:Command", default="", namespaces=ns)
    arguments = root.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=ns)
    boot = root.find(".//t:BootTrigger", ns) is not None
    if uri != TASK_NAME or logon_type.casefold() != "s4u" or not boot:
        raise WatchdogError("orphan_task_contract_mismatch")
    command_path = Path(command)
    argument_path = Path(arguments.strip().strip('"'))
    if not _same_file(command_path, python_executable) or not _same_file(
        argument_path,
        launcher,
    ):
        raise WatchdogError("orphan_task_action_mismatch")


def inspect_orphaned_task_file(
    *,
    python_executable: Path,
    launcher: Path,
) -> dict[str, Any] | None:
    if task_status().get("exists"):
        return None
    task_file = _task_file_path()
    if not task_file.exists():
        return None
    if not task_file.is_file() or task_file.is_symlink():
        raise WatchdogError("orphan_task_file_invalid")
    payload = task_file.read_bytes()
    _validate_orphan_task_xml(
        payload,
        python_executable=python_executable,
        launcher=launcher,
    )
    return {
        "present": True,
        "task_name": TASK_NAME,
        "task_file": str(task_file),
        "task_file_sha256": _sha256_bytes(payload),
    }


def _reconcile_orphaned_task_file(
    runtime_root: Path,
    *,
    python_executable: Path,
    launcher: Path,
    invocation_id: str,
) -> dict[str, Any] | None:
    inspected = inspect_orphaned_task_file(
        python_executable=python_executable,
        launcher=launcher,
    )
    if inspected is None:
        return None
    task_file = Path(inspected["task_file"])
    payload = task_file.read_bytes()
    digest = str(inspected["task_file_sha256"])
    backup_root = runtime_root / "backups" / "orphaned-scheduled-task" / digest
    backup_file = backup_root / "DesktopPc24x7RuntimeWatchdog.xml"
    manifest_path = backup_root / "manifest.json"
    manifest = {
        "task_name": TASK_NAME,
        "task_file_sha256": digest,
        "invocation_id": invocation_id,
        "quarantined_at": now_iso(),
    }
    if backup_root.exists():
        try:
            existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise WatchdogError("orphan_task_backup_collision") from None
        if not isinstance(existing_manifest, dict) or (
            existing_manifest.get("task_name") != TASK_NAME
            or existing_manifest.get("task_file_sha256") != digest
            or not backup_file.is_file()
            or backup_file.is_symlink()
            or _sha256_bytes(backup_file.read_bytes()) != digest
        ):
            raise WatchdogError("orphan_task_backup_collision")
    else:
        backup_root.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=digest + ".", dir=backup_root.parent))
        try:
            atomic_bytes(staging / backup_file.name, payload)
            atomic_json(staging / manifest_path.name, manifest)
            os.replace(staging, backup_root)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    if _sha256_bytes(task_file.read_bytes()) != digest:
        raise WatchdogError("orphan_task_changed_before_quarantine")
    task_file.unlink()
    return {
        "reconciled": True,
        "task_file_sha256": digest,
        "backup_file": str(backup_file),
    }


def _restore_orphaned_task_file(reconciliation: dict[str, Any] | None) -> None:
    if not reconciliation or task_status().get("exists"):
        return
    task_file = _task_file_path()
    if task_file.exists():
        return
    backup_file = Path(str(reconciliation["backup_file"]))
    payload = backup_file.read_bytes()
    if _sha256_bytes(payload) != reconciliation["task_file_sha256"]:
        raise WatchdogError("orphan_task_backup_integrity_failed")
    atomic_bytes(task_file, payload)


def _task_headless_ready(task: dict[str, Any]) -> bool:
    return (
        task.get("exists") is True
        and task.get("trigger_at_startup") is True
        and str(task.get("logon_type") or "").casefold() == "s4u"
    )


def register_task_from_metadata(
    metadata_path: Path,
    *,
    invocation_id: str = "direct-elevated",
) -> dict[str, Any]:
    installation = load_installed_metadata(metadata_path, require_current_release=True)
    reconciliation = _reconcile_orphaned_task_file(
        installation["runtime_root"],
        python_executable=installation["python_executable"],
        launcher=installation["launcher"],
        invocation_id=invocation_id,
    )
    try:
        registered = register_boot_task(
            python_executable=installation["python_executable"],
            launcher=installation["launcher"],
        )
        observed = task_status()
        if not _task_headless_ready(observed):
            raise WatchdogError("task_scheduler_elevated_readback_failed")
    except Exception:
        _restore_orphaned_task_file(reconciliation)
        raise
    return {
        **registered,
        "elevated_readback": observed,
        "orphan_reconciled": bool(reconciliation),
        "orphan_task_file_sha256": (
            reconciliation.get("task_file_sha256") if reconciliation else None
        ),
    }


def current_user_id() -> str:
    import getpass
    return f"{socket.gethostname()}\\{getpass.getuser()}"


def current_user_sid(user_id: str) -> str:
    try:
        import win32security  # type: ignore
    except ImportError as exc:
        raise WatchdogError("pywin32 indisponível para resolver SID da tarefa") from exc
    try:
        sid, _, _ = win32security.LookupAccountName(None, user_id)
        value = str(win32security.ConvertSidToStringSid(sid))
    except Exception as exc:
        raise WatchdogError("task_principal_sid_unavailable") from exc
    parts = value.split("-")
    if len(parts) < 4 or parts[0] != "S" or any(not part.isdigit() for part in parts[1:]):
        raise WatchdogError("task_principal_sid_invalid")
    return value


def task_security_descriptor(user_sid: str) -> str:
    parts = user_sid.split("-")
    if len(parts) < 4 or parts[0] != "S" or any(not part.isdigit() for part in parts[1:]):
        raise WatchdogError("task_principal_sid_invalid")
    return f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;{user_sid})"


def register_boot_task(*, python_executable: Path, launcher: Path) -> dict[str, Any]:
    require_windows_desktop()
    try:
        import win32com.client  # type: ignore
    except ImportError as exc:
        raise WatchdogError("pywin32 indisponível para registrar tarefa AtStartup") from exc

    service = win32com.client.Dispatch("Schedule.Service")
    service.Connect()
    try:
        folder = service.GetFolder(TASK_FOLDER)
    except Exception:
        root = service.GetFolder("\\")
        folder = root.CreateFolder(TASK_FOLDER.lstrip("\\"))

    definition = service.NewTask(0)
    definition.RegistrationInfo.Description = (
        "Desktop PC24x7 runtime watchdog: RDC + dedicated GitHub Actions runner"
    )
    definition.Settings.Enabled = True
    definition.Settings.StartWhenAvailable = True
    definition.Settings.DisallowStartIfOnBatteries = False
    definition.Settings.StopIfGoingOnBatteries = False
    definition.Settings.MultipleInstances = TASK_INSTANCES_IGNORE_NEW
    definition.Settings.ExecutionTimeLimit = "PT0S"
    restart_policy_supported = True
    try:
        definition.Settings.RestartCount = 999
        definition.Settings.RestartInterval = "PT1M"
    except Exception:
        restart_policy_supported = False

    trigger = definition.Triggers.Create(TASK_TRIGGER_BOOT)
    trigger.Enabled = True
    trigger.Delay = "PT20S"

    action = definition.Actions.Create(TASK_ACTION_EXEC)
    action.Path = str(python_executable)
    action.Arguments = f'"{launcher}"'
    action.WorkingDirectory = str(launcher.parent)

    principal = definition.Principal
    principal.UserId = current_user_id()
    principal.LogonType = TASK_LOGON_S4U
    principal.RunLevel = TASK_RUNLEVEL_LUA
    task_sddl = task_security_descriptor(current_user_sid(principal.UserId))

    try:
        registered_task = folder.RegisterTaskDefinition(
            TASK_LEAF,
            definition,
            TASK_CREATE_OR_UPDATE,
            principal.UserId,
            None,
            TASK_LOGON_S4U,
            task_sddl,
        )
        registered_task.SetSecurityDescriptor(task_sddl, 0)
    except Exception as exc:
        detail = repr(exc).casefold()
        if (
            "-2147024891" in detail
            or "0x80070005" in detail
            or "access is denied" in detail
            or "acesso negado" in detail
        ):
            raise WatchdogError("task_scheduler_access_denied") from exc
        raise WatchdogError(f"registro AtStartup falhou: {type(exc).__name__}") from exc

    return {
        "ok": True,
        "task_name": TASK_NAME,
        "trigger": "AtStartup",
        "logon_type": "S4U",
        "password_used": False,
        "run_level": "limited",
        "restart_policy_supported": restart_policy_supported,
        "task_acl_applied": True,
    }


def _schtasks() -> Path:
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    target = root / "System32" / "schtasks.exe"
    if not target.is_file():
        raise WatchdogError("schtasks.exe não encontrado")
    return target


def run_watchdog_task() -> dict[str, Any]:
    completed = subprocess.run(
        [str(_schtasks()), "/Run", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False) or "utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise WatchdogError("tarefa watchdog não pôde ser iniciada")
    return {"run_returncode": completed.returncode}


def task_runtime_snapshot() -> dict[str, Any]:
    if os.name != "nt":
        raise WatchdogError("Windows Task Scheduler obrigatório")
    try:
        import win32com.client  # type: ignore

        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        task = service.GetFolder(TASK_FOLDER).GetTask(TASK_LEAF)
        return {
            "state": int(task.State),
            "last_task_result": int(task.LastTaskResult),
            "enabled": bool(task.Enabled),
        }
    except Exception as exc:
        raise WatchdogError("leitura runtime da tarefa watchdog falhou") from exc


def stop_watchdog_task(
    runtime_root: Path, *, timeout_seconds: int = 15
) -> dict[str, Any]:
    before = task_runtime_snapshot()
    if before["state"] != 4:
        lock = wait_watchdog_lock_released(
            runtime_root, timeout_seconds=timeout_seconds
        )
        return {
            "stopped": False,
            "state_before": before["state"],
            "lock_release": lock,
        }
    try:
        import win32com.client  # type: ignore

        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        task = service.GetFolder(TASK_FOLDER).GetTask(TASK_LEAF)
        task.Stop(0)
    except Exception as exc:
        raise WatchdogError("tarefa watchdog não pôde ser parada") from exc
    deadline = time.monotonic() + max(1, min(timeout_seconds, 30))
    while time.monotonic() < deadline:
        observed = task_runtime_snapshot()
        if observed["state"] != 4:
            lock = wait_watchdog_lock_released(
                runtime_root, timeout_seconds=timeout_seconds
            )
            return {
                "stopped": True,
                "state_before": before["state"],
                "state_after": observed["state"],
                "lock_release": lock,
            }
        time.sleep(0.25)
    raise WatchdogError("tarefa watchdog permaneceu em execução após Stop")


def task_status() -> dict[str, Any]:
    if os.name != "nt":
        return {"exists": False, "trigger_at_startup": False}
    completed = subprocess.run(
        [str(_schtasks()), "/Query", "/TN", TASK_NAME, "/XML"],
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False) or "utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        return {"exists": False, "trigger_at_startup": False}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(completed.stdout)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        boot = root.find(".//t:BootTrigger", ns) is not None
        logon_type = root.findtext(".//t:Principal/t:LogonType", default="", namespaces=ns)
    except Exception as exc:
        return {
            "exists": True,
            "trigger_at_startup": False,
            "parse_error": type(exc).__name__,
        }
    return {
        "exists": True,
        "trigger_at_startup": boot,
        "task_name": TASK_NAME,
        "logon_type": logon_type,
    }


def install(
    source_root: Path,
    *,
    source_sha: str,
    python_executable: Path,
    runner_home: Path | None,
    runtime_root: Path,
    watch_interval_seconds: int,
    confirm: str,
) -> dict[str, Any]:
    if confirm != CONFIRM:
        raise WatchdogError("confirmação inválida")
    host = require_windows_desktop()
    if len(source_sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in source_sha):
        raise WatchdogError("source_sha inválido")
    source_root = source_root.resolve()
    discovered_runner = discover_runner_home(runner_home)
    release_root = runtime_root / "releases" / source_sha.lower()
    _copy_release(source_root, release_root)
    launcher = _write_launcher(runtime_root)

    metadata = {
        "schema_version": "1",
        "service": SERVICE_NAME,
        "host": host,
        "source_sha": source_sha.lower(),
        "runtime_root": str(runtime_root),
        "release_root": str(release_root),
        "python_executable": str(python_executable.resolve()),
        "runner_home": str(discovered_runner),
        "watch_interval_seconds": max(10, int(watch_interval_seconds)),
        "installed_at": now_iso(),
        "production_touched": False,
        "secrets_read": False,
    }
    metadata_path = runtime_root / "metadata.json"
    atomic_json(metadata_path, metadata)
    activation_pending = False
    requires_uac_activation = False
    try:
        task = register_boot_task(
            python_executable=python_executable.resolve(),
            launcher=launcher,
        )
        started = run_watchdog_task()
        headless_boot_ready = bool(
            task.get("trigger") == "AtStartup"
            and str(task.get("logon_type") or "").casefold() == "s4u"
        )
    except WatchdogError as exc:
        if str(exc) != "task_scheduler_access_denied":
            raise
        task = task_status()
        started = {"started": False, "reason": "uac_activation_required"}
        headless_boot_ready = False
        activation_pending = True
        requires_uac_activation = True

    result = {
        "ok": True,
        "host": host,
        "service": SERVICE_NAME,
        "source_sha": source_sha.lower(),
        "runtime_root": str(runtime_root),
        "runner_home": str(discovered_runner),
        "task": task,
        "start": started,
        "headless_boot_ready": headless_boot_ready,
        "activation_pending": activation_pending,
        "requires_uac_activation": requires_uac_activation,
        "uac_launcher": str(release_root / "scripts" / UAC_LAUNCHER_SCRIPT),
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
        "installed_at": now_iso(),
    }
    atomic_json(runtime_root / "install-evidence.json", result)
    return result


def status(runtime_root: Path) -> dict[str, Any]:
    state: dict[str, Any] = {}
    state_path = runtime_root / "state.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {"ok": False, "error": "state_invalid"}
    return {
        "host": socket.gethostname(),
        "task": task_status(),
        "state": state,
        "metadata_present": (runtime_root / "metadata.json").is_file(),
    }


def _inventory_path(path: Path, *, directory: bool) -> None:
    """Check existing components without following a reparse point."""
    import stat
    if not path.is_absolute() or ".." in path.parts or path.drive.startswith("\\\\"):
        raise WatchdogError("inventory_path_rejected")
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise WatchdogError("inventory_link_rejected")
        valid = stat.S_ISDIR(info.st_mode) if part != path or directory else stat.S_ISREG(info.st_mode)
        if not valid:
            raise WatchdogError("inventory_path_type_rejected")


def _inventory_bytes(path: Path, limit: int = 2097152) -> bytes:
    _inventory_path(path, directory=False)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise WatchdogError("inventory_file_too_large")
    return raw


def _inventory_json(path: Path) -> tuple[dict[str, Any], str]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    raw = _inventory_bytes(path, 65536)
    value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value, hashlib.sha256(raw).hexdigest()


def _inventory_same_path(value: Any, expected: Path) -> bool:
    return (
        isinstance(value, str) and Path(value).is_absolute()
        and ".." not in Path(value).parts
        and os.path.normcase(str(Path(value))) == os.path.normcase(str(expected))
    )


def _inventory_failure(exc: Exception) -> str:
    if isinstance(exc, FileNotFoundError):
        return "missing"
    if isinstance(exc, (ValueError, UnicodeError)):
        return "invalid"
    if isinstance(exc, WatchdogError):
        return "blocked"
    return "unavailable"


def _inventory_task_identity(installation: dict[str, Any] | None) -> dict[str, Any]:
    """Read only the fixed task; keep principal, SID and action text private."""
    import win32api  # type: ignore
    import win32com.client  # type: ignore
    import win32security  # type: ignore

    service = win32com.client.Dispatch("Schedule.Service")
    service.Connect()
    task = service.GetFolder(TASK_FOLDER).GetTask(TASK_LEAF)
    definition = task.Definition
    principal = str(definition.Principal.UserId)
    if principal.startswith("S-"):
        task_sid = str(win32security.ConvertSidToStringSid(
            win32security.ConvertStringSidToSid(principal)
        ))
    else:
        task_sid = current_user_sid(principal)
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 0x0008)
    try:
        process_sid = str(win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        ))
    finally:
        token.Close()
    result = {
        "process_user_matches_task_principal": process_sid == task_sid,
        "task_s4u": int(definition.Principal.LogonType) == TASK_LOGON_S4U,
        "task_limited": int(definition.Principal.RunLevel) == TASK_RUNLEVEL_LUA,
        "task_action_matches_installation": None,
    }
    if installation is not None:
        matches = False
        if int(definition.Actions.Count) == 1:
            action = definition.Actions.Item(1)
            matches = (
                int(action.Type) == TASK_ACTION_EXEC
                and _inventory_same_path(str(action.Path), installation["python_executable"])
                and str(action.Arguments) == f'"{installation["launcher"]}"'
                and _inventory_same_path(str(action.WorkingDirectory), installation["runtime_root"])
            )
        result["task_action_matches_installation"] = matches
    return result


def readonly_local_inventory() -> dict[str, Any]:
    """Fixed PDQ inventory. Never starts, stops, configures or authenticates."""
    from pc24x7_host_policy import orchestrator_dev_runner_profile

    host = require_windows_desktop()
    profile = orchestrator_dev_runner_profile(host)
    result: dict[str, Any] = {
        "paths_status": "unavailable",
        "metadata_status": "unavailable", "installed_source_sha": None,
        "metadata_sha256": None, "watchdog_sha256": None, "uac_sha256": None,
        "launcher_sha256": None, "host_policy_sha256": None,
        "metadata_host_matches": None, "metadata_runner_home_matches": None,
        "metadata_release_matches": None, "metadata_python_exists": None,
        "task_query_status": "unavailable", "task_registered_observed": None,
        "task_at_startup": None, "task_runtime_status": "unavailable",
        "task_state": None, "task_enabled": None,
        "task_identity_status": "unavailable", "task_s4u": None, "task_limited": None,
        "process_user_matches_task_principal": None,
        "task_action_matches_installation": None,
        "state_status": "unavailable", "state_ok": None,
        "state_source_matches_installation": None, "state_fresh_300s": None,
        "runtime_home_status": "unavailable", "runtime_listener_pid": None,
        "runtime_unresolved_process_count": None,
        "orchestrator_home_status": "unavailable",
        "orchestrator_home_empty": None, "orchestrator_config_present": None,
    }
    root = primary = extra = None
    installation = None
    try:
        local = Path(os.environ.get("LOCALAPPDATA") or "")
        _inventory_path(local, directory=True)
        root = default_runtime_root()
        primary = local / "DesktopPC24x7" / "GitHubRunner"
        extra = local / profile["directory"] / "GitHubRunner"
        result["paths_status"] = "observed"
    except Exception as exc:
        result["paths_status"] = _inventory_failure(exc)

    if root is not None:
        try:
            metadata, fingerprint = _inventory_json(root / "metadata.json")
            result["metadata_sha256"] = fingerprint
            source = metadata.get("source_sha")
            if not isinstance(source, str) or len(source) != 40 or any(c not in "0123456789abcdefABCDEF" for c in source):
                raise ValueError("installed_sha_invalid")
            source = source.lower()
            result["installed_source_sha"] = source
            release = root / "releases" / source
            result["metadata_host_matches"] = str(metadata.get("host", "")).casefold() == host.casefold()
            result["metadata_runner_home_matches"] = _inventory_same_path(metadata.get("runner_home"), primary)
            result["metadata_release_matches"] = _inventory_same_path(metadata.get("release_root"), release)
            if not (
                _inventory_same_path(metadata.get("runtime_root"), root)
                and result["metadata_host_matches"]
                and result["metadata_runner_home_matches"]
                and result["metadata_release_matches"]
            ):
                raise ValueError("metadata_scope_mismatch")
            python = metadata.get("python_executable")
            if not isinstance(python, str):
                raise ValueError("python_path_invalid")
            _inventory_path(Path(python), directory=False)
            result["metadata_python_exists"] = True
            for field, path in (
                ("watchdog_sha256", release / "scripts" / "desktop_control_plane_watchdog.py"),
                ("uac_sha256", release / "scripts" / UAC_LAUNCHER_SCRIPT),
                ("host_policy_sha256", release / "scripts" / HOST_POLICY_SCRIPT),
                ("launcher_sha256", root / "run.py"),
            ):
                try:
                    result[field] = hashlib.sha256(_inventory_bytes(path)).hexdigest()
                except Exception:
                    result[field] = None
            candidate = load_installed_metadata(root / "metadata.json")
            after, after_fingerprint = _inventory_json(root / "metadata.json")
            if candidate["metadata"] != metadata or after != metadata or after_fingerprint != fingerprint:
                raise ValueError("metadata_changed_during_read")
            installation = candidate
            result["metadata_status"] = "observed"
        except Exception as exc:
            result["metadata_status"] = _inventory_failure(exc)
        try:
            state, _ = _inventory_json(root / "state.json")
            result["state_ok"] = state.get("ok") if type(state.get("ok")) is bool else None
            if result["installed_source_sha"] is not None:
                result["state_source_matches_installation"] = state.get("source_sha") == result["installed_source_sha"]
            generated = datetime.fromisoformat(str(state.get("generated_at", "")).replace("Z", "+00:00"))
            if generated.tzinfo is None:
                raise ValueError("state_time_invalid")
            age = (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds()
            result["state_fresh_300s"] = 0 <= age <= 300
            result["state_status"] = "observed"
        except Exception as exc:
            result["state_status"] = _inventory_failure(exc)

    try:
        task = task_status()
        result["task_registered_observed"] = task.get("exists") is True
        result["task_at_startup"] = task.get("trigger_at_startup") is True
        result["task_query_status"] = "observed" if task.get("exists") is True else "unavailable"
    except Exception as exc:
        result["task_query_status"] = _inventory_failure(exc)
    try:
        task_runtime = task_runtime_snapshot()
        result["task_state"] = task_runtime["state"]
        result["task_enabled"] = task_runtime["enabled"]
        result["task_runtime_status"] = "observed"
    except Exception as exc:
        result["task_runtime_status"] = _inventory_failure(exc)
    try:
        result.update(_inventory_task_identity(installation))
        result["task_identity_status"] = "observed"
    except Exception as exc:
        result["task_identity_status"] = _inventory_failure(exc)

    if primary is not None:
        try:
            _inventory_path(primary, directory=True)
            for parts in RUNNER_REQUIRED:
                _inventory_path(primary.joinpath(*parts), directory=False)
            process = runner_process_snapshot(primary)
            matching = process["matching_pids"]
            result["runtime_listener_pid"] = matching[0] if len(matching) == 1 else None
            result["runtime_unresolved_process_count"] = len(process["unresolved_pids"])
            result["runtime_home_status"] = "observed"
        except Exception as exc:
            result["runtime_home_status"] = _inventory_failure(exc)
    if extra is not None:
        try:
            _inventory_path(extra, directory=True)
            result["orchestrator_home_empty"] = not any(extra.iterdir())
            try:
                _inventory_path(extra / ".runner", directory=False)
                result["orchestrator_config_present"] = True
            except FileNotFoundError:
                result["orchestrator_config_present"] = False
            result["orchestrator_home_status"] = "observed"
        except Exception as exc:
            result["orchestrator_home_status"] = _inventory_failure(exc)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    install_parser = sub.add_parser("install")
    install_parser.add_argument("--source-root", type=Path, required=True)
    install_parser.add_argument("--source-sha", required=True)
    install_parser.add_argument("--python-executable", type=Path, default=Path(sys.executable))
    install_parser.add_argument("--runner-home", type=Path)
    install_parser.add_argument("--runtime-root", type=Path, default=None)
    install_parser.add_argument("--watch-interval-seconds", type=int, default=DEFAULT_WATCH_SECONDS)
    install_parser.add_argument("--confirm", required=True)

    watch_parser = sub.add_parser("watch")
    watch_parser.add_argument("--metadata", type=Path, required=True)

    status_parser = sub.add_parser("status")
    status_parser.add_argument("--runtime-root", type=Path, default=None)

    register_parser = sub.add_parser("register-task-com")
    register_parser.add_argument("--metadata", type=Path, required=True)
    register_parser.add_argument("--receipt", type=Path)
    register_parser.add_argument("--invocation-id")

    ns = parser.parse_args()
    try:
        if ns.command == "install":
            runtime_root = ns.runtime_root or default_runtime_root()
            payload = install(
                ns.source_root,
                source_sha=ns.source_sha,
                python_executable=ns.python_executable,
                runner_home=ns.runner_home,
                runtime_root=runtime_root,
                watch_interval_seconds=ns.watch_interval_seconds,
                confirm=ns.confirm,
            )
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0
        if ns.command == "watch":
            return watch(ns.metadata)
        if ns.command == "status":
            runtime_root = ns.runtime_root or default_runtime_root()
            print(json.dumps(status(runtime_root), ensure_ascii=False, sort_keys=True))
            return 0
        if ns.command == "register-task-com":
            payload = register_task_from_metadata(
                ns.metadata,
                invocation_id=ns.invocation_id or "direct-elevated",
            )
            if ns.receipt or ns.invocation_id:
                if not ns.receipt or not ns.invocation_id:
                    raise WatchdogError("recibo UAC incompleto")
                receipt = ns.receipt.resolve()
                expected = ns.metadata.resolve().parent / "uac-result.json"
                if receipt != expected:
                    raise WatchdogError("caminho de recibo UAC inválido")
                atomic_json(
                    receipt,
                    {
                        "ok": True,
                        "invocation_id": ns.invocation_id,
                        "completed_at": now_iso(),
                        "task": payload,
                    },
                )
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0
        raise WatchdogError("comando inválido")
    except (WatchdogError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        if (
            getattr(ns, "command", None) == "register-task-com"
            and getattr(ns, "receipt", None)
            and getattr(ns, "invocation_id", None)
        ):
            receipt = ns.receipt.resolve()
            expected = ns.metadata.resolve().parent / "uac-result.json"
            if receipt == expected:
                atomic_json(
                    receipt,
                    {
                        "ok": False,
                        "invocation_id": ns.invocation_id,
                        "completed_at": now_iso(),
                        "error": str(exc)[:1000],
                        "error_type": type(exc).__name__,
                    },
                )
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc)[:1000],
                    "error_type": type(exc).__name__,
                    "production_touched": False,
                    "secrets_read": False,
                    "reboot_performed": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
