#!/usr/bin/env python3
"""Broker administrativo governado do Desktop PC24x7 Runtime.

Canal outbound-only:
- consulta somente a issue operacional #2 do reposit�rio desktop-pc24x7-runtime;
- aceita somente coment�rios exatos do owner;
- n�o abre porta de rede local;
- n�o aceita shell, caminho, execut�vel, host ou argumento arbitr�rio;
- executa somente handlers versionados e idempotentes;
- nesta etapa n�o ativa/substitui o watchdog legado.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXPECTED_HOST = "DESKTOP-PDQK954"  # compatibility default; authorization is host-policy driven
EXPECTED_ACTOR = "ericson-j-santos"
EXPECTED_ASSOCIATION = "OWNER"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
REPOSITORY_URL = "https://github.com/ericson-j-santos/desktop-pc24x7-runtime.git"
ISSUE_NUMBER = 2
TASK_FOLDER = r"\Automation"
TASK_LEAF = "DesktopPc24x7AdminBroker"
TASK_NAME = TASK_FOLDER + "\\" + TASK_LEAF
TASK_TRIGGER_BOOT = 8
TASK_ACTION_EXEC = 0
TASK_LOGON_S4U = 2
TASK_CREATE_OR_UPDATE = 6
TASK_RUNLEVEL_HIGHEST = 1
TASK_INSTANCES_IGNORE_NEW = 2
USER_RUN_KEY = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
USER_RUN_VALUE = "DesktopPc24x7AdminBroker"
USER_AUTOSTART_MODE = "HKCU_RUN_AT_LOGON"
INSTALL_CONFIRM = "INSTALL-DESKTOP-ADMIN-BROKER"
DEFAULT_POLL_SECONDS = 300
MAX_COMMENT_AGE_SECONDS = 1800
BROKER_LOCK_FILE = "broker.lock"
BROKER_LOCK_TIMEOUT_SECONDS = 900.0
BROKER_LOCK_POLL_SECONDS = 0.25
METADATA_LOCK_FILE = "metadata.lock"
METADATA_LOCK_TIMEOUT_SECONDS = 30.0
WATCHDOG_SCRIPT = "desktop_control_plane_watchdog.py"
WATCHDOG_UAC_SCRIPT = "desktop_control_plane_watchdog_uac_launcher.py"
RDC_RECOVERY_SCRIPT = "pc24x7_rdc_recovery.py"
RUNNER_BOOTSTRAP_SCRIPT = "activate_desktop_runtime_runner.py"
READBACK_SCRIPT = "desktop_admin_broker_readback.py"
PERSISTED_PYTHON_DIR = "python-runtime"
BROKER_HEARTBEAT_FILE = "broker-heartbeat.json"
BROKER_HEARTBEAT_INTERVAL_SECONDS = 30
BROKER_SUPERVISOR_VERSION = "2"

ALLOWED_COMMANDS = {
    "/desktop-runtime admin status": "status",
    "/desktop-runtime admin recover-rdc": "recover-rdc",
    "/desktop-runtime admin recover-runner": "recover-runner",
    "/desktop-runtime admin recover-control-plane": "recover-control-plane",
    "/desktop-runtime admin activate-watchdog": "activate-watchdog",
    "/desktop-runtime admin refresh-self": "refresh-self",
    "/desktop-runtime admin windows-component-health": "windows-component-health",
    "/desktop-runtime admin qualify-orchestrator-runner-acl": "qualify-orchestrator-runner-acl",
}


class BrokerError(RuntimeError):
    pass


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def require_windows_desktop() -> str:
    if os.name != "nt":
        raise BrokerError("Windows obrigat�rio")
    host = socket.gethostname()
    # The pinned Desktop remains authorized even when a legacy updater staged
    # a release without pc24x7_host_policy.py; every other host fails closed.
    if host.casefold() != EXPECTED_HOST.casefold():
        raise BrokerError("host n�o autorizado: " + host)
    return host


def validate_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise BrokerError("source_sha inv�lido")
    return value


def default_runtime_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise BrokerError("LOCALAPPDATA n�o definido")
    return Path(base) / "DesktopPC24x7" / "AdminBroker"


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_python_version(python_executable: Path) -> str:
    completed = subprocess.run(
        [str(python_executable), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    observed = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0 or not observed.startswith("Python "):
        raise BrokerError("python_runtime_probe_failed")
    return observed.removeprefix("Python ").strip()


def _python_source_root(python_executable: Path) -> Path:
    executable = python_executable.resolve()
    if not executable.is_file():
        raise BrokerError("python_executable_missing")
    root = executable.parent
    if (root / "pyvenv.cfg").is_file() or (root.parent / "pyvenv.cfg").is_file():
        raise BrokerError("python_virtualenv_not_persistable")
    runtime_markers = (
        root / "python3.dll",
        root / "python312.dll",
        root / "python312.zip",
        root / "Lib",
    )
    if not any(path.exists() for path in runtime_markers):
        raise BrokerError("python_runtime_source_incomplete")
    return root


def stage_persistent_python(
    python_executable: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    source_executable = python_executable.resolve()
    source_root = _python_source_root(source_executable)
    source_hash = _sha256_file(source_executable)
    version = _probe_python_version(source_executable)

    destination_root = (
        runtime_root.resolve()
        / PERSISTED_PYTHON_DIR
        / source_hash[:16]
    )
    destination_executable = destination_root / source_executable.name
    reused = destination_root.is_dir()

    if not reused:
        destination_root.parent.mkdir(parents=True, exist_ok=True)
        staging = destination_root.with_name(
            destination_root.name + f".tmp-{os.getpid()}"
        )
        if staging.exists():
            shutil.rmtree(staging)
        try:
            shutil.copytree(source_root, staging, symlinks=False)
            staged_executable = staging / source_executable.name
            if not staged_executable.is_file():
                raise BrokerError("persisted_python_executable_missing")
            if _sha256_file(staged_executable) != source_hash:
                raise BrokerError("persisted_python_hash_mismatch")
            if _probe_python_version(staged_executable) != version:
                raise BrokerError("persisted_python_version_mismatch")
            os.replace(staging, destination_root)
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    if not destination_executable.is_file():
        raise BrokerError("persisted_python_executable_missing")
    if _sha256_file(destination_executable) != source_hash:
        raise BrokerError("persisted_python_hash_mismatch")
    if _probe_python_version(destination_executable) != version:
        raise BrokerError("persisted_python_version_mismatch")

    return {
        "python_executable": destination_executable.resolve(),
        "runtime_root": destination_root.resolve(),
        "version": version,
        "executable_sha256": source_hash,
        "reused": reused,
    }


def parse_github_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise BrokerError("timestamp GitHub sem timezone")
    return parsed.astimezone(timezone.utc)


def authorize_comment(
    comment: dict[str, Any],
    *,
    not_before: datetime,
    reference_time: datetime | None = None,
) -> str | None:
    reference = reference_time or now_utc()
    user = comment.get("user") or {}
    if str(user.get("login") or "").casefold() != EXPECTED_ACTOR.casefold():
        return None
    if str(comment.get("author_association") or "").upper() != EXPECTED_ASSOCIATION:
        return None
    body = str(comment.get("body") or "").strip()
    action = ALLOWED_COMMANDS.get(body)
    if action is None:
        return None
    created = parse_github_time(str(comment.get("created_at") or ""))
    updated = parse_github_time(str(comment.get("updated_at") or ""))
    if updated != created:
        return None
    if created < not_before:
        return None
    age = (reference - created).total_seconds()
    if age < -60 or age > MAX_COMMENT_AGE_SECONDS:
        return None
    return action


def github_comments_url(since: datetime) -> str:
    encoded = urllib.parse.quote(since.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))
    return (
        f"https://api.github.com/repos/{REPOSITORY}/issues/{ISSUE_NUMBER}/comments"
        f"?since={encoded}&per_page=100"
    )


def fetch_comments(since: datetime, timeout_seconds: float = 20.0) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        github_comments_url(since),
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Desktop-PC24x7-Runtime-Admin-Broker/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, list):
        raise BrokerError("resposta GitHub inv�lida")
    return [item for item in payload if isinstance(item, dict)]


def _load_module(path: Path, name: str):
    if not path.is_file():
        raise BrokerError(f"script governado ausente: {path.name}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BrokerError(f"script governado n�o carreg�vel: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def watchdog_runtime_metadata() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise BrokerError("LOCALAPPDATA n�o definido")
    return Path(base) / "DesktopPC24x7" / "ControlPlaneWatchdog" / "metadata.json"


def _watchdog_module(metadata: dict[str, Any]):
    path = Path(metadata["release_root"]) / "scripts" / WATCHDOG_SCRIPT
    return _load_module(path, "desktop_runtime_broker_watchdog")


def _readback_module(metadata: dict[str, Any]):
    path = Path(metadata["release_root"]) / "scripts" / READBACK_SCRIPT
    return _load_module(path, "desktop_runtime_broker_readback")


def _publish_readback(metadata: dict[str, Any], accepted: dict[str, Any]) -> dict[str, Any]:
    try:
        module = _readback_module(metadata)
        return module.publish_readback(
            accepted=accepted,
            source_sha=validate_sha(str(metadata["source_sha"])),
            host=EXPECTED_HOST,
        )
    except Exception:
        return {
            "published": False,
            "channel": "ntfy",
            "authoritative": False,
            "error_code": "readback_publish_failed",
        }


def _ensure_watchdog_staged(metadata: dict[str, Any]) -> tuple[Any, Path]:
    target = watchdog_runtime_metadata()
    release_root = Path(metadata["release_root"])
    staged = _load_module(
        release_root / "scripts" / WATCHDOG_SCRIPT,
        "desktop_runtime_broker_watchdog_stage",
    )
    if not target.is_file():
        result = staged.install(
            release_root,
            source_sha=metadata["source_sha"],
            python_executable=Path(sys.executable),
            runner_home=None,
            runtime_root=staged.default_runtime_root(),
            watch_interval_seconds=30,
            confirm=staged.CONFIRM,
        )
        if result.get("ok") is not True and result.get("activation_pending") is not True:
            raise BrokerError("watchdog n�o p�de ser preparado")
    if not target.is_file():
        raise BrokerError("metadata do watchdog n�o foi criada")
    return staged, target


def _activate_watchdog(metadata: dict[str, Any]) -> dict[str, Any]:
    _, target = _ensure_watchdog_staged(metadata)
    release_root = Path(metadata["release_root"])
    scripts = release_root / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        launcher = _load_module(scripts / WATCHDOG_UAC_SCRIPT, "desktop_runtime_broker_watchdog_launcher")
        result = launcher.launch(
            target,
            confirm=launcher.LAUNCH_CONFIRM,
            timeout_seconds=15,
        )
    finally:
        try:
            sys.path.remove(str(scripts))
        except ValueError:
            pass
    if result.get("ok") is not True:
        raise BrokerError("ativa��o governada do watchdog n�o concluiu")
    return {
        "handler": "activate-watchdog",
        "watchdog_result": result.get("result"),
        "task": result.get("task"),
    }


def _recover_runner(metadata: dict[str, Any]) -> dict[str, Any]:
    release_root = Path(metadata["release_root"])
    script = release_root / "scripts" / RUNNER_BOOTSTRAP_SCRIPT
    if not script.is_file():
        raise BrokerError("runner bootstrap governado ausente na release")

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--confirm",
            "ACTIVATE-DESKTOP-RUNTIME-RUNNER",
            "--repo-root",
            str(release_root),
            "--source-sha",
            validate_sha(str(metadata["source_sha"])),
            "--non-interactive-auth",
        ],
        cwd=release_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=420,
        check=False,
    )
    payload: dict[str, Any] = {}
    for line in reversed(completed.stdout.splitlines()):
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            payload = candidate
            break

    if not payload:
        raise BrokerError("runner_bootstrap_evidence_missing")
    state = str(payload.get("state") or "unknown")[:120]
    local_recovery_ok = (
        payload.get("local_recovery_ok") is True
        and payload.get("runner_running") is True
        and payload.get("github_pickup_required") is True
    )
    full_success = completed.returncode == 0 and payload.get("ok") is True
    bounded_partial = completed.returncode in {0, 3} and local_recovery_ok
    if not (full_success or bounded_partial):
        raise BrokerError(f"runner_bootstrap_failed:{state}")

    return {
        "handler": "recover-runner",
        "bootstrap_state": state,
        "runner_running": bool(payload.get("runner_running")),
        "local_recovery_ok": bool(payload.get("local_recovery_ok")),
        "github_pickup_required": bool(payload.get("github_pickup_required")),
        "github_pickup_proven": False,
        "runner_registry_present": payload.get("runner_registry_present"),
        "runner_registry_status": str(payload.get("runner_registry_status") or "unknown")[:40],
        "runner_registry_labels_ok": payload.get("runner_registry_labels_ok"),
        "runner_registered_now": bool(payload.get("runner_registered_now")),
        "runner_started_now": bool(payload.get("runner_started_now")),
    }


def _recover_rdc(metadata: dict[str, Any], correlation_id: str) -> dict[str, Any]:
    release_root = Path(metadata["release_root"])
    script = release_root / "scripts" / RDC_RECOVERY_SCRIPT
    evidence = Path(metadata["runtime_root"]) / "evidence" / f"{correlation_id}.rdc.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--confirm",
            "RECOVER-GOVERNED-RDC",
            "--correlation-id",
            correlation_id,
            "--evidence-file",
            str(evidence),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        check=False,
    )
    payload = json.loads(evidence.read_text(encoding="utf-8")) if evidence.is_file() else {}
    if completed.returncode != 0 or payload.get("ok") is not True:
        raise BrokerError("recupera��o governada do RDC falhou")
    return {
        "handler": "recover-rdc",
        "mode": payload.get("mode"),
        "owner": payload.get("owner"),
        "fallback_armed": bool(payload.get("fallback_armed")),
    }


def _recover_control_plane(metadata: dict[str, Any]) -> dict[str, Any]:
    target = watchdog_runtime_metadata()
    if not target.is_file():
        raise BrokerError("watchdog_metadata_missing")
    installed = json.loads(target.read_text(encoding="utf-8"))
    watchdog = _watchdog_module(installed)

    # Recover the runner first through the already-installed runtime. Persistence
    # of the watchdog must not block immediate runner recovery and must not
    # trigger GUI/UAC from this command path.
    cycle = watchdog.cycle(installed)
    runner_ok = (
        cycle.get("runner_recovery_ok") is True
        or (cycle.get("github_runner") or {}).get("status")
        in {"recovered", "process_running"}
    )
    if not runner_ok:
        raise BrokerError("runner_recovery_failed")

    task = watchdog.task_status()
    task_ready = (
        task.get("exists") is True
        and task.get("trigger_at_startup") is True
        and str(task.get("logon_type") or "").casefold() == "s4u"
    )
    if task_ready:
        try:
            start = watchdog.run_watchdog_task()
            activation = {
                "ok": True,
                "status": "already_ready",
                "task": task,
                "start": start,
            }
        except Exception:
            activation = {
                "ok": False,
                "status": "persistence_start_failed",
                "error_code": "watchdog_task_start_failed",
                "task": task,
            }
    else:
        activation = {
            "ok": False,
            "status": "persistence_pending",
            "error_code": "watchdog_task_not_headless_ready",
            "task": task,
        }

    return {
        "handler": "recover-control-plane",
        "activation": activation,
        "cycle": cycle,
        "github_pickup_required": True,
        "github_pickup_proven": False,
        "local_recovery_ok": True,
    }


def _git_executable() -> Path:
    located = shutil.which("git")
    if not located:
        raise BrokerError("self_refresh_git_missing")
    return Path(located).resolve()


def _run_git(
    git: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: float = 180.0,
) -> str:
    completed = subprocess.run(
        [str(git), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise BrokerError("self_refresh_git_failed")
    return completed.stdout.strip()


def _remote_main_sha(git: Path) -> str:
    output = _run_git(
        git,
        ["ls-remote", "--exit-code", REPOSITORY_URL, "refs/heads/main"],
        timeout_seconds=60,
    )
    rows = [line.split() for line in output.splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != "refs/heads/main":
        raise BrokerError("self_refresh_main_ref_invalid")
    return validate_sha(rows[0][0])


def task_ready(task: dict[str, Any]) -> bool:
    return (
        task.get("exists") is True
        and task.get("trigger_at_startup") is True
        and str(task.get("logon_type") or "").casefold() == "s4u"
        and str(task.get("run_level") or "").casefold() == "highest"
        and task.get("enabled") is True
    )


def _elevated_task_proven(metadata: dict[str, Any]) -> bool:
    task = metadata.get("admin_task")
    return (
        metadata.get("admin_channel_ready") is True
        and isinstance(task, dict)
        and task_ready(task)
    )


def _fallback_persistence_ready(status: dict[str, Any]) -> bool:
    return (
        status.get("mode") == USER_AUTOSTART_MODE
        and status.get("readback_verified") is True
    )


def _reconcile_activation_metadata(
    metadata: dict[str, Any],
    *,
    python_executable: Path,
    launcher: Path,
) -> dict[str, Any]:
    """Falha fechado sem promover metadata para o estado administrativo."""
    reconciled = dict(metadata)
    if _elevated_task_proven(reconciled):
        observed_task = task_status()
        if task_ready(observed_task):
            return reconciled

    fallback = user_autostart_status(
        python_executable=python_executable,
        launcher=launcher,
    )
    if not _fallback_persistence_ready(fallback):
        fallback = register_user_autostart(
            python_executable=python_executable,
            launcher=launcher,
        )
    if not _fallback_persistence_ready(fallback):
        raise BrokerError("user_autostart_readback_mismatch")

    persisted_fallback = reconciled.get("fallback_persistence")
    fallback_metadata = (
        dict(persisted_fallback) if isinstance(persisted_fallback, dict) else {}
    )
    fallback_metadata.update(fallback)

    reconciled.update(
        {
            "activation_pending": True,
            "requires_uac_activation": True,
            "admin_channel_ready": False,
            "fallback_persistence": fallback_metadata,
            "fallback_start_requested": True,
            "functional_success_proven": False,
        }
    )
    return reconciled


def _load_refresh_metadata(metadata_path: Path, current_sha: str) -> dict[str, Any]:
    latest = load_installed_metadata(metadata_path)["metadata"]
    if validate_sha(str(latest["source_sha"])) != current_sha:
        raise BrokerError("self_refresh_metadata_changed")
    return latest


def _reconcile_activation_metadata_file(
    metadata_path: Path,
    *,
    python_executable: Path,
    launcher: Path,
    expected_sha: str | None = None,
) -> dict[str, Any]:
    """Reconcilia o fallback sem manter metadata.lock durante I/O f�sico."""
    for _attempt in range(3):
        base = load_installed_metadata(metadata_path)["metadata"]
        if expected_sha is not None:
            observed_sha = validate_sha(str(base["source_sha"]))
            if observed_sha != expected_sha:
                raise BrokerError("self_refresh_metadata_changed")

        reconciled = _reconcile_activation_metadata(
            base,
            python_executable=python_executable,
            launcher=launcher,
        )
        lock_handle = _acquire_metadata_lock(metadata_path)
        try:
            latest = load_installed_metadata(metadata_path)["metadata"]
            if latest != base:
                continue
            if reconciled != latest:
                atomic_json(metadata_path, reconciled)
            return reconciled
        finally:
            _release_broker_lock(lock_handle)
    raise BrokerError("metadata_reconcile_contention")


def _restore_previous_release_after_failed_start(
    *,
    metadata_path: Path,
    runtime_root: Path,
    python_executable: Path,
    previous: dict[str, Any],
    attempted: dict[str, Any],
    activation_launcher: Path,
) -> None:
    """Roll back only our exact metadata write; never overwrite another writer.

    This restores local metadata and the fixed activation launcher. It does NOT
    claim that either broker process is alive or that a physical runner recovered.
    """
    handle = _acquire_metadata_lock(metadata_path)
    try:
        observed = load_installed_metadata(metadata_path)["metadata"]
        if observed != attempted:
            raise BrokerError("self_refresh_rollback_conflict")
        previous_sha = validate_sha(str(previous["source_sha"]))
        previous_release = (runtime_root / "releases" / previous_sha).resolve()
        if (
            Path(str(previous["release_root"])).resolve() != previous_release
            or not (previous_release / "scripts" / "desktop_admin_broker.py").is_file()
        ):
            raise BrokerError("self_refresh_previous_release_unavailable")
        restored_launcher = _write_uac_activation_launcher(
            runtime_root,
            release_root=previous_release,
            python_executable=python_executable,
            metadata_path=metadata_path,
        )
        if Path(restored_launcher).resolve() != Path(activation_launcher).resolve():
            raise BrokerError("self_refresh_rollback_launcher_mismatch")
        atomic_json(metadata_path, previous)
        if load_installed_metadata(metadata_path)["metadata"] != previous:
            raise BrokerError("self_refresh_rollback_readback_failed")
    finally:
        _release_broker_lock(handle)


def _self_refresh(metadata: dict[str, Any]) -> dict[str, Any]:
    require_windows_desktop()
    current_sha = validate_sha(str(metadata["source_sha"]))
    runtime_root = Path(str(metadata["runtime_root"])).resolve()
    metadata_path = runtime_root / "metadata.json"
    python_executable = Path(str(metadata["python_executable"])).resolve()
    launcher = runtime_root / "run.py"

    git = _git_executable()
    target_sha = _remote_main_sha(git)
    if target_sha == current_sha:
        _reconcile_activation_metadata_file(
            metadata_path,
            python_executable=python_executable,
            launcher=launcher,
            expected_sha=current_sha,
        )
        return {
            "handler": "refresh-self",
            "refresh_state": "already_current",
            "previous_source_sha": current_sha,
            "target_source_sha": target_sha,
            "new_broker_started": False,
        }

    staging_root = runtime_root / "refresh-staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="refresh-", dir=str(staging_root)) as temp:
        clone = Path(temp) / "repo"
        _run_git(
            git,
            [
                "clone",
                "--filter=blob:none",
                "--no-tags",
                "--depth",
                "1",
                "--branch",
                "main",
                REPOSITORY_URL,
                str(clone),
            ],
            timeout_seconds=180,
        )
        observed_sha = validate_sha(
            _run_git(git, ["-C", str(clone), "rev-parse", "HEAD"], timeout_seconds=30)
        )
        if observed_sha != target_sha:
            raise BrokerError("self_refresh_sha_mismatch")
        if _run_git(git, ["-C", str(clone), "status", "--porcelain"], timeout_seconds=30):
            raise BrokerError("self_refresh_source_dirty")

        release = runtime_root / "releases" / target_sha
        _copy_release(clone, release)
        release_broker = release / "scripts" / "desktop_admin_broker.py"
        if not release_broker.is_file():
            raise BrokerError("self_refresh_release_incomplete")

        activation_launcher = _write_uac_activation_launcher(
            runtime_root,
            release_root=release,
            python_executable=python_executable,
            metadata_path=metadata_path,
        )
        _reconcile_activation_metadata_file(
            metadata_path,
            python_executable=python_executable,
            launcher=launcher,
            expected_sha=current_sha,
        )
        lock_handle = _acquire_metadata_lock(metadata_path)
        try:
            latest_metadata = _load_refresh_metadata(metadata_path, current_sha)
            updated = dict(latest_metadata)
            updated.update(
                {
                    "previous_source_sha": current_sha,
                    "source_sha": target_sha,
                    "release_root": str(release),
                    "activation_launcher": str(activation_launcher),
                    "poll_seconds": DEFAULT_POLL_SECONDS,
                    "refreshed_at": now_iso(),
                    "refresh_source": "canonical_main",
                }
            )
            atomic_json(metadata_path, updated)
        finally:
            _release_broker_lock(lock_handle)

    try:
        start = start_user_broker(
            python_executable=python_executable,
            launcher=launcher,
        )
        if start.get("startup_survived") is not True:
            raise BrokerError("user_broker_start_not_confirmed")
    except Exception:
        _restore_previous_release_after_failed_start(
            metadata_path=metadata_path,
            runtime_root=runtime_root,
            python_executable=python_executable,
            previous=latest_metadata,
            attempted=updated,
            activation_launcher=activation_launcher,
        )
        raise
    return {
        "handler": "refresh-self",
        "refresh_state": "updated",
        "previous_source_sha": current_sha,
        "target_source_sha": target_sha,
        "new_broker_started": bool(start.get("startup_survived")),
    }


def _heartbeat_path(metadata: dict[str, Any]) -> Path:
    return Path(metadata["runtime_root"]) / BROKER_HEARTBEAT_FILE


def _write_heartbeat(metadata: dict[str, Any], **updates: Any) -> dict[str, Any]:
    """Persiste um readback sanitizado para provar que o broker est� vivo."""
    path = _heartbeat_path(metadata)
    payload: dict[str, Any] = {}
    if path.is_file():
        try:
            candidate = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                payload.update(candidate)
        except (OSError, json.JSONDecodeError):
            payload = {}
    payload.update(
        {
            "schema_version": "1",
            "supervisor_version": BROKER_SUPERVISOR_VERSION,
            "pid": os.getpid(),
            "source_sha": str(metadata.get("source_sha") or "")[:40],
            "updated_at": now_iso(),
            "production_touched": False,
            "secrets_read": False,
            "reboot_performed": False,
        }
    )
    payload.update(updates)
    atomic_json(path, payload)
    return payload


def _heartbeat_is_fresh(payload: dict[str, Any], *, reference_time: datetime | None = None) -> bool:
    try:
        observed = parse_github_time(str(payload.get("updated_at") or ""))
    except Exception:
        return False
    reference = reference_time or now_utc()
    return 0 <= (reference - observed).total_seconds() <= max(
        90, BROKER_HEARTBEAT_INTERVAL_SECONDS * 3
    )


def _status(metadata: dict[str, Any]) -> dict[str, Any]:
    watchdog_state = {}
    target = watchdog_runtime_metadata()
    if target.is_file():
        installed = json.loads(target.read_text(encoding="utf-8"))
        state = Path(installed["runtime_root"]) / "state.json"
        if state.is_file():
            watchdog_state = json.loads(state.read_text(encoding="utf-8"))
    heartbeat = {}
    heartbeat_file = _heartbeat_path(metadata)
    if heartbeat_file.is_file():
        try:
            candidate = json.loads(heartbeat_file.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                heartbeat = candidate
        except (OSError, json.JSONDecodeError):
            heartbeat = {}
    try:
        supervisor_receipt = _readback_module(metadata).supervisor_receipt_status()
    except Exception:
        supervisor_receipt = {"state": "unavailable"}
    return {
        "handler": "status",
        "supervisor_receipt": supervisor_receipt,
        "broker_task": task_status(),
        "watchdog_state": watchdog_state,
        "broker_runtime": {
            "ready": _heartbeat_is_fresh(heartbeat),
            "heartbeat": heartbeat,
            "admin_activation_pending": bool(metadata.get("requires_uac_activation")),
            "admin_channel_ready": bool(metadata.get("admin_channel_ready")),
            "fallback_autostart": metadata.get("fallback_persistence"),
        },
    }


def _windows_component_health(metadata: dict[str, Any], correlation_id: str) -> dict[str, Any]:
    runtime_root = Path(metadata["runtime_root"])
    evidence = runtime_root / "evidence" / f"{correlation_id}.windows-component-health.json"
    if evidence.is_file():
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        if payload.get("correlation_id") == correlation_id and payload.get("completed") is True:
            return {"handler": "windows-component-health", "reused": True, "receipt": evidence.name,
                    "checkhealth_exit": payload.get("checkhealth_exit"),
                    "scanhealth_exit": payload.get("scanhealth_exit"),
                    "sfc_verifyonly_exit": payload.get("sfc_verifyonly_exit"),
                    "configci_present": payload.get("configci_present"),
                    "cipolicy_schema_present": payload.get("cipolicy_schema_present")}
    if os.name != "nt":
        raise BrokerError("windows_component_health_requires_windows")
    commands = (
        ("checkhealth_exit", ["dism.exe", "/Online", "/Cleanup-Image", "/CheckHealth"], 180),
        ("scanhealth_exit", ["dism.exe", "/Online", "/Cleanup-Image", "/ScanHealth"], 900),
        ("sfc_verifyonly_exit", ["sfc.exe", "/verifyonly"], 900),
    )
    payload = {"schema": "desktop-windows-component-health/v1", "correlation_id": correlation_id,
               "completed": False, "production_touched": False}
    for key, argv, timeout in commands:
        completed = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=timeout, check=False)
        payload[key] = completed.returncode
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    payload["configci_present"] = (system_root / "System32" / "WindowsPowerShell" / "v1.0" / "Modules" / "ConfigCI").is_dir()
    payload["cipolicy_schema_present"] = (system_root / "schemas" / "CodeIntegrity" / "cipolicy.xsd").is_file()
    payload["completed"] = True
    atomic_json(evidence, payload)
    return {"handler": "windows-component-health", "reused": False, "receipt": evidence.name,
            "checkhealth_exit": payload["checkhealth_exit"], "scanhealth_exit": payload["scanhealth_exit"],
            "sfc_verifyonly_exit": payload["sfc_verifyonly_exit"],
            "configci_present": payload["configci_present"],
            "cipolicy_schema_present": payload["cipolicy_schema_present"]}


def _enable_windows_privilege(name: str) -> bool:
    """Enable one privilege already assigned to this fixed broker process."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    class LUID(ctypes.Structure):
        _fields_ = (("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG))

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = (("PrivilegeCount", wintypes.DWORD), ("Luid", LUID),
                    ("Attributes", wintypes.DWORD))

    token=[REDACTED]
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        privileges = TOKEN_PRIVILEGES(1, luid, 0x00000002)
        ctypes.set_last_error(0)
        adjusted = advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(privileges), 0, None, None
        )
        return bool(adjusted) and ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def _read_named_security_descriptor(path: Path) -> tuple[str, str | None]:
    """Read owner/group/DACL as SDDL without taking ownership or changing access."""
    if os.name != "nt":
        return "windows_required", None
    import ctypes
    from ctypes import wintypes

    attributes = ctypes.WinDLL("kernel32", use_last_error=True).GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF:
        error = ctypes.get_last_error()
        return ("missing" if error in {2, 3} else "access_denied" if error == 5
                else f"winerror_{error}"), None
    if attributes & 0x400:
        return "reparse_point_rejected", None

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    security_information = 0x00000001 | 0x00000002 | 0x00000004
    status = advapi32.GetNamedSecurityInfoW(
        str(path), 1, security_information, None, None, None, None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        return ("access_denied" if status == 5 else f"winerror_{status}"), None
    rendered = ctypes.c_void_p()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, security_information, ctypes.byref(rendered), None
        ):
            error = ctypes.get_last_error()
            return f"render_winerror_{error}", None
        return "observed", ctypes.cast(rendered, ctypes.c_wchar_p).value
    finally:
        if rendered.value:
            kernel32.LocalFree(rendered)
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def _query_fixed_task_xml(task_name: str) -> tuple[str, str | None]:
    if task_name not in {
        r"\Automation\DesktopPc24x7RuntimeWatchdog",
        r"\Automation\DesktopPc24x7RuntimeHealthSupervisor",
        r"\Automation\DesktopPc24x7AdminBroker",
    }:
        raise BrokerError("task_name_not_allowlisted")
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    completed = subprocess.run(
        [str(system_root / "System32" / "schtasks.exe"), "/Query", "/TN", task_name, "/XML"],
        capture_output=True, timeout=20, check=False,
    )
    if completed.returncode != 0:
        return "not_observed_or_unavailable", None
    if len(completed.stdout) > 262144:
        return "response_too_large", None
    encoding = "utf-16" if completed.stdout.startswith(b"\xff\xfe") or b"\x00" in completed.stdout[:80] else "utf-8-sig"
    try:
        return "observed", completed.stdout.decode(encoding)
    except UnicodeError:
        return "invalid_encoding", None


def _fixed_orchestrator_runner_targets() -> dict[str, Path]:
    local = Path(str(os.environ.get("LOCALAPPDATA") or ""))
    profile = Path(str(os.environ.get("USERPROFILE") or ""))
    if not local.is_absolute() or not profile.is_absolute():
        raise BrokerError("profile_path_unavailable")
    try:
        local.resolve(strict=False).relative_to(profile.resolve(strict=False))
    except (OSError, ValueError):
        raise BrokerError("localappdata_profile_mismatch") from None
    home = local / "EngineeringOrchestratorDEV" / "GitHubRunner"
    return {"runner_home": home, "runner_metadata": home / ".runner"}


def _qualify_orchestrator_runner_acl(
    metadata: dict[str, Any], correlation_id: str,
) -> dict[str, Any]:
    """Capture an exact private backup and return only bounded public evidence."""
    require_windows_desktop()
    runtime_root = Path(metadata["runtime_root"])
    evidenc