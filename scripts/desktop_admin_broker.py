#!/usr/bin/env python3
"""Broker administrativo governado do Desktop PC24x7 Runtime.

Canal outbound-only:
- consulta somente a issue operacional #2 do repositório desktop-pc24x7-runtime;
- aceita somente comentários exatos do owner;
- não abre porta de rede local;
- não aceita shell, caminho, executável, host ou argumento arbitrário;
- executa somente handlers versionados e idempotentes;
- nesta etapa não ativa/substitui o watchdog legado.
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

EXPECTED_HOST = "DESKTOP-PDQK954"
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
}


class BrokerError(RuntimeError):
    pass


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def require_windows_desktop() -> str:
    if os.name != "nt":
        raise BrokerError("Windows obrigatório")
    host = socket.gethostname()
    if host.casefold() != EXPECTED_HOST.casefold():
        raise BrokerError(f"host não autorizado: {host}")
    return host


def validate_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise BrokerError("source_sha inválido")
    return value


def default_runtime_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise BrokerError("LOCALAPPDATA não definido")
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
        raise BrokerError("resposta GitHub inválida")
    return [item for item in payload if isinstance(item, dict)]


def _load_module(path: Path, name: str):
    if not path.is_file():
        raise BrokerError(f"script governado ausente: {path.name}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BrokerError(f"script governado não carregável: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def watchdog_runtime_metadata() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise BrokerError("LOCALAPPDATA não definido")
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
            raise BrokerError("watchdog não pôde ser preparado")
    if not target.is_file():
        raise BrokerError("metadata do watchdog não foi criada")
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
        raise BrokerError("ativação governada do watchdog não concluiu")
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
        raise BrokerError("recuperação governada do RDC falhou")
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
    """Reconcilia o fallback sem manter metadata.lock durante I/O físico."""
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

    start = start_user_broker(
        python_executable=python_executable,
        launcher=launcher,
    )
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
    """Persiste um readback sanitizado para provar que o broker está vivo."""
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
    return {
        "handler": "status",
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


def execute_action(action: str, metadata: dict[str, Any], comment_id: int) -> dict[str, Any]:
    correlation_id = f"desktop-admin-gh-comment-{comment_id}"
    if action == "status":
        result = _status(metadata)
    elif action == "recover-rdc":
        result = _recover_rdc(metadata, correlation_id)
    elif action == "recover-runner":
        result = _recover_runner(metadata)
    elif action == "recover-control-plane":
        result = _recover_control_plane(metadata)
    elif action == "activate-watchdog":
        result = _activate_watchdog(metadata)
    elif action == "refresh-self":
        result = _self_refresh(metadata)
    else:
        raise BrokerError("action_id não allowlisted")
    return {
        "ok": True,
        "action": action,
        "comment_id": comment_id,
        "correlation_id": correlation_id,
        "result": result,
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
        "completed_at": now_iso(),
    }


def state_path(metadata: dict[str, Any]) -> Path:
    return Path(metadata["runtime_root"]) / "state.json"


def load_state(metadata: dict[str, Any]) -> dict[str, Any]:
    path = state_path(metadata)
    if not path.is_file():
        return {
            "last_seen_comment_id": 0,
            "last_seen_at": metadata["not_before"],
        }
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise BrokerError("state inválido")
    return payload


def process_once(metadata: dict[str, Any], *, reference_time: datetime | None = None) -> dict[str, Any]:
    state = load_state(metadata)
    not_before = parse_github_time(metadata["not_before"])
    since = parse_github_time(str(state.get("last_seen_at") or metadata["not_before"]))
    last_seen = int(state.get("last_seen_comment_id") or 0)
    comments = sorted(fetch_comments(since), key=lambda item: int(item.get("id") or 0))
    accepted = 0
    restart_requested = False
    for comment in comments:
        comment_id = int(comment.get("id") or 0)
        if comment_id <= last_seen:
            continue
        created = parse_github_time(str(comment.get("created_at") or metadata["not_before"]))
        action = authorize_comment(
            comment,
            not_before=not_before,
            reference_time=reference_time,
        )
        state["last_seen_comment_id"] = comment_id
        state["last_seen_at"] = created.isoformat()
        state["observed_at"] = now_iso()
        if action is None:
            atomic_json(state_path(metadata), state)
            last_seen = comment_id
            continue
        state["accepted"] = {
            "comment_id": comment_id,
            "action": action,
            "status": "inflight",
            "accepted_at": now_iso(),
        }
        atomic_json(state_path(metadata), state)
        try:
            outcome = execute_action(action, metadata, comment_id)
            state["accepted"] = {
                "comment_id": comment_id,
                "action": action,
                "status": "completed",
                "outcome": outcome,
            }
        except Exception as exc:
            error_code = type(exc).__name__
            if isinstance(exc, BrokerError):
                controlled = str(exc).strip()
                if controlled and len(controlled) <= 120 and all(
                    ch.isalnum() or ch in "_:-" for ch in controlled
                ):
                    error_code = controlled
            state["accepted"] = {
                "comment_id": comment_id,
                "action": action,
                "status": "failed",
                "error_code": error_code,
            }
        state["observed_at"] = now_iso()
        atomic_json(state_path(metadata), state)
        state["readback"] = _publish_readback(metadata, state["accepted"])
        state["observed_at"] = now_iso()
        atomic_json(state_path(metadata), state)
        accepted += 1
        last_seen = comment_id
        if action == "refresh-self" and state["accepted"].get("status") == "completed":
            refresh = state["accepted"].get("outcome", {}).get("result", {})
            if refresh.get("refresh_state") == "updated":
                restart_requested = refresh.get("new_broker_started") is True
                break
    return {
        "ok": True,
        "comments_seen": len(comments),
        "commands_accepted": accepted,
        "last_seen_comment_id": last_seen,
        "restart_requested": restart_requested,
    }


def _lock_contention(exc: OSError) -> bool:
    if os.name == "nt":
        winerror = getattr(exc, "winerror", None)
        if winerror is not None:
            return winerror in {32, 33}
    return exc.errno in {errno.EACCES, errno.EAGAIN}


def _try_lock_broker_file(handle: Any) -> bool:
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if _lock_contention(exc):
            return False
        raise BrokerError("broker_lock_failed") from exc
    return True


def _acquire_file_lock(
    runtime_root: Path,
    *,
    lock_file: str,
    timeout_seconds: float = BROKER_LOCK_TIMEOUT_SECONDS,
    poll_seconds: float = BROKER_LOCK_POLL_SECONDS,
    timeout_error: str = "broker_lock_timeout",
) -> Any:
    path = runtime_root / lock_file
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        handle = path.open("a+b")
    except OSError as exc:
        raise BrokerError("broker_lock_open_failed") from exc
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            if _try_lock_broker_file(handle):
                return handle
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrokerError(timeout_error)
            time.sleep(min(max(0.01, poll_seconds), remaining))
    except Exception:
        handle.close()
        raise


def _acquire_broker_lock(
    runtime_root: Path,
    *,
    timeout_seconds: float = BROKER_LOCK_TIMEOUT_SECONDS,
    poll_seconds: float = BROKER_LOCK_POLL_SECONDS,
) -> Any:
    return _acquire_file_lock(
        runtime_root,
        lock_file=BROKER_LOCK_FILE,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
    )


def _acquire_metadata_lock(metadata_path: Path) -> Any:
    return _acquire_file_lock(
        metadata_path.parent,
        lock_file=METADATA_LOCK_FILE,
        timeout_seconds=METADATA_LOCK_TIMEOUT_SECONDS,
        poll_seconds=BROKER_LOCK_POLL_SECONDS,
        timeout_error="metadata_lock_timeout",
    )


def _release_broker_lock(handle: Any) -> None:
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def watch(metadata_path: Path) -> int:
    installation = load_installed_metadata(metadata_path)
    lock_handle = _acquire_broker_lock(installation["runtime_root"])
    try:
        metadata = load_installed_metadata(metadata_path)["metadata"]
        _write_heartbeat(metadata, status="running", started_at=now_iso())
        persisted_elevated = _elevated_task_proven(metadata)
        try:
            physical_task_ready = persisted_elevated and task_ready(task_status())
        except Exception:
            physical_task_ready = False
        lock_owner_was_degraded = not physical_task_ready
        while True:
            metadata = load_installed_metadata(metadata_path)["metadata"]
            interval = max(
                30,
                min(int(metadata.get("poll_seconds") or DEFAULT_POLL_SECONDS), 300),
            )
            try:
                _write_heartbeat(metadata, status="running", last_cycle_started_at=now_iso())
                if lock_owner_was_degraded and _elevated_task_proven(metadata):
                    if task_ready(task_status()):
                        _write_heartbeat(
                            metadata,
                            status="handoff_to_elevated_task",
                            stopped_at=now_iso(),
                        )
                        return 0
                    metadata = _reconcile_activation_metadata_file(
                        metadata_path,
                        python_executable=installation["python_executable"],
                        launcher=installation["launcher"],
                    )
                cycle = process_once(metadata)
                _write_heartbeat(
                    metadata,
                    status="running",
                    last_cycle_completed_at=now_iso(),
                    last_cycle_ok=True,
                )
                if cycle.get("restart_requested") is True:
                    _write_heartbeat(
                        metadata,
                        status="handoff_after_refresh",
                        stopped_at=now_iso(),
                    )
                    return 0
            except Exception as exc:
                state = load_state(metadata)
                state["broker_error"] = {
                    "error": str(exc)[:1000],
                    "error_type": type(exc).__name__,
                    "observed_at": now_iso(),
                }
                atomic_json(state_path(metadata), state)
                _write_heartbeat(
                    metadata,
                    status="degraded_retrying",
                    last_error_code=type(exc).__name__,
                )
            deadline = time.monotonic() + interval
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                _write_heartbeat(metadata, status="running")
                time.sleep(min(BROKER_HEARTBEAT_INTERVAL_SECONDS, remaining))
    finally:
        try:
            _write_heartbeat(
                metadata,
                status="stopped",
                stopped_at=now_iso(),
            )
        finally:
            _release_broker_lock(lock_handle)


def current_user_id() -> str:
    import getpass
    return f"{socket.gethostname()}\\{getpass.getuser()}"


def _scheduler():
    try:
        import win32com.client  # type: ignore
    except ImportError as exc:
        raise BrokerError("pywin32 indisponível") from exc
    service = win32com.client.Dispatch("Schedule.Service")
    service.Connect()
    return service


def _user_autostart_command(*, python_executable: Path, launcher: Path) -> str:
    return subprocess.list2cmdline(
        [str(python_executable.resolve()), str(launcher.resolve())]
    )


def user_autostart_status(*, python_executable: Path, launcher: Path) -> dict[str, Any]:
    """Lê e valida o fallback per-user sem alterar o Registro."""
    require_windows_desktop()
    try:
        import winreg
    except ImportError as exc:
        raise BrokerError("winreg_unavailable") from exc

    command = _user_autostart_command(
        python_executable=python_executable,
        launcher=launcher,
    )
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            USER_RUN_KEY,
            0,
            winreg.KEY_QUERY_VALUE,
        ) as key:
            observed, value_type = winreg.QueryValueEx(key, USER_RUN_VALUE)
    except FileNotFoundError:
        return {
            "ok": False,
            "exists": False,
            "mode": USER_AUTOSTART_MODE,
            "value_name": USER_RUN_VALUE,
            "readback_verified": False,
            "requires_admin": False,
        }
    except OSError as exc:
        raise BrokerError("user_autostart_status_failed") from exc
    verified = value_type == winreg.REG_SZ and str(observed) == command
    return {
        "ok": verified,
        "exists": True,
        "mode": USER_AUTOSTART_MODE,
        "value_name": USER_RUN_VALUE,
        "readback_verified": verified,
        "requires_admin": False,
    }


def register_user_autostart(*, python_executable: Path, launcher: Path) -> dict[str, Any]:
    """Registra fallback per-user fixo e sem privilégio administrativo."""
    require_windows_desktop()
    try:
        import winreg
    except ImportError as exc:
        raise BrokerError("winreg_unavailable") from exc

    command = _user_autostart_command(
        python_executable=python_executable,
        launcher=launcher,
    )
    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            USER_RUN_KEY,
            0,
            access,
        ) as key:
            winreg.SetValueEx(key, USER_RUN_VALUE, 0, winreg.REG_SZ, command)
            observed, value_type = winreg.QueryValueEx(key, USER_RUN_VALUE)
    except OSError as exc:
        raise BrokerError("user_autostart_registration_failed") from exc
    if value_type != winreg.REG_SZ or str(observed) != command:
        raise BrokerError("user_autostart_readback_mismatch")
    return {
        "ok": True,
        "exists": True,
        "mode": USER_AUTOSTART_MODE,
        "value_name": USER_RUN_VALUE,
        "readback_verified": True,
        "requires_admin": False,
    }


def remove_user_autostart() -> dict[str, Any]:
    """Remove o fallback depois que AtStartup + S4U estiver disponível."""
    require_windows_desktop()
    try:
        import winreg
    except ImportError as exc:
        raise BrokerError("winreg_unavailable") from exc
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            USER_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            try:
                winreg.DeleteValue(key, USER_RUN_VALUE)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise BrokerError("user_autostart_remove_failed") from exc
    return {"ok": True, "removed": True}


def start_user_broker(*, python_executable: Path, launcher: Path) -> dict[str, Any]:
    """Inicia o fallback fixo e rejeita processo que morre imediatamente."""
    require_windows_desktop()
    python_path = python_executable.resolve()
    launcher_path = launcher.resolve()
    if not python_path.is_file():
        raise BrokerError("persisted_python_executable_missing")
    if not launcher_path.is_file():
        raise BrokerError("broker_launcher_missing")
    flags = 0
    if os.name == "nt":
        flags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        flags |= int(getattr(subprocess, "DETACHED_PROCESS", 0))
    process = subprocess.Popen(
        [str(python_path), str(launcher_path)],
        cwd=launcher_path.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        creationflags=flags,
    )
    time.sleep(1.0)
    exit_code = process.poll()
    if exit_code is not None:
        raise BrokerError("user_broker_start_failed")
    return {
        "requested": True,
        "pid": int(process.pid),
        "startup_survived": True,
        "functional_success_proven": False,
    }


def register_task(*, python_executable: Path, launcher: Path) -> dict[str, Any]:
    require_windows_desktop()
    service = _scheduler()
    try:
        folder = service.GetFolder(TASK_FOLDER)
    except Exception:
        folder = service.GetFolder("\\").CreateFolder(TASK_FOLDER.lstrip("\\"))
    definition = service.NewTask(0)
    definition.RegistrationInfo.Description = "Desktop PC24x7 Runtime governed admin broker"
    definition.Settings.Enabled = True
    definition.Settings.StartWhenAvailable = True
    definition.Settings.MultipleInstances = TASK_INSTANCES_IGNORE_NEW
    definition.Settings.ExecutionTimeLimit = "PT0S"
    definition.Settings.RestartCount = 999
    definition.Settings.RestartInterval = "PT1M"
    trigger = definition.Triggers.Create(TASK_TRIGGER_BOOT)
    trigger.Enabled = True
    trigger.Delay = "PT30S"
    action = definition.Actions.Create(TASK_ACTION_EXEC)
    action.Path = str(python_executable)
    action.Arguments = f'"{launcher}"'
    action.WorkingDirectory = str(launcher.parent)
    principal = definition.Principal
    principal.UserId = current_user_id()
    principal.LogonType = TASK_LOGON_S4U
    principal.RunLevel = TASK_RUNLEVEL_HIGHEST
    try:
        folder.RegisterTaskDefinition(
            TASK_LEAF,
            definition,
            TASK_CREATE_OR_UPDATE,
            principal.UserId,
            "",
            TASK_LOGON_S4U,
        )
    except Exception as exc:
        detail = repr(exc).casefold()
        if "0x80070005" in detail or "-2147024891" in detail or "access is denied" in detail or "acesso negado" in detail:
            raise BrokerError("task_scheduler_access_denied") from exc
        raise BrokerError(f"registro do broker falhou: {type(exc).__name__}") from exc
    return {
        "ok": True,
        "task_name": TASK_NAME,
        "trigger": "AtStartup",
        "logon_type": "S4U",
        "run_level": "highest",
        "password_used": False,
    }


def task_status() -> dict[str, Any]:
    try:
        service = _scheduler()
        folder = service.GetFolder(TASK_FOLDER)
        task = folder.GetTask(TASK_LEAF)
        definition = task.Definition
        trigger_at_startup = any(
            definition.Triggers.Item(i).Type == TASK_TRIGGER_BOOT
            for i in range(1, definition.Triggers.Count + 1)
        )
        return {
            "exists": True,
            "trigger_at_startup": trigger_at_startup,
            "logon_type": "S4U" if definition.Principal.LogonType == TASK_LOGON_S4U else str(definition.Principal.LogonType),
            "run_level": "highest" if definition.Principal.RunLevel == TASK_RUNLEVEL_HIGHEST else str(definition.Principal.RunLevel),
            "enabled": bool(task.Enabled),
        }
    except Exception:
        return {"exists": False, "trigger_at_startup": False}


def run_task() -> dict[str, Any]:
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    schtasks = root / "System32" / "schtasks.exe"
    completed = subprocess.run(
        [str(schtasks), "/Run", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise BrokerError("falha ao iniciar tarefa do broker")
    return {"run_returncode": completed.returncode}


def _copy_release(source_root: Path, release_root: Path) -> None:
    scripts = release_root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    for name in (
        "desktop_admin_broker.py",
        "desktop_admin_broker_uac_launcher.py",
        WATCHDOG_SCRIPT,
        WATCHDOG_UAC_SCRIPT,
        RDC_RECOVERY_SCRIPT,
        RUNNER_BOOTSTRAP_SCRIPT,
        READBACK_SCRIPT,
    ):
        source = source_root / "scripts" / name
        if not source.is_file():
            raise BrokerError(f"script obrigatório ausente: {name}")
        destination = scripts / name
        destination.write_bytes(source.read_bytes())


def _write_launcher(runtime_root: Path) -> Path:
    """Gera um supervisor per-user que mantém o broker vivo sem nova UAC."""
    launcher = runtime_root / "run.py"
    launcher.write_text(
        "from pathlib import Path\n"
        "import json, os, runpy, sys, time\n"
        "metadata = Path(__file__).with_name('metadata.json')\n"
        "heartbeat = metadata.with_name('broker-heartbeat.json')\n"
        "restart_delay = 5\n"
        "restart_count = 0\n"
        "while True:\n"
        "    payload = json.loads(metadata.read_text(encoding='utf-8'))\n"
        "    script = Path(payload['release_root']) / 'scripts' / 'desktop_admin_broker.py'\n"
        "    try:\n"
        "        sys.argv = [str(script), 'watch', '--metadata', str(metadata)]\n"
        "        runpy.run_path(str(script), run_name='__main__')\n"
        "        latest = json.loads(metadata.read_text(encoding='utf-8'))\n"
        "        if latest.get('admin_channel_ready') is True and latest.get('requires_uac_activation') is False:\n"
        "            break\n"
        "        restart_count += 1\n"
        "        time.sleep(restart_delay)\n"
        "    except SystemExit as exc:\n"
        "        code = exc.code if isinstance(exc.code, int) else 0\n"
        "        if code == 0:\n"
        "            try:\n"
        "                latest = json.loads(metadata.read_text(encoding='utf-8'))\n"
        "            except Exception:\n"
        "                latest = {}\n"
        "            if latest.get('admin_channel_ready') is True and latest.get('requires_uac_activation') is False:\n"
        "                break\n"
        "            restart_count += 1\n"
        "            time.sleep(restart_delay)\n"
        "            continue\n"
        "        time.sleep(restart_delay)\n"
        "    except Exception as exc:\n"
        "        try:\n"
        "            observed = {}\n"
        "            if heartbeat.is_file():\n"
        "                candidate = json.loads(heartbeat.read_text(encoding='utf-8'))\n"
        "                if isinstance(candidate, dict):\n"
        "                    observed.update(candidate)\n"
        "            observed.update({'pid': os.getpid(), 'status': 'supervisor_retrying', 'restart_count': restart_count, 'last_error_code': type(exc).__name__, 'updated_at': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(), 'production_touched': False, 'secrets_read': False, 'reboot_performed': False})\n"
        "            heartbeat.write_text(json.dumps(observed, sort_keys=True), encoding='utf-8')\n"
        "        except Exception:\n"
        "            pass\n"
        "        restart_count += 1\n"
        "        time.sleep(restart_delay)\n",
        encoding="utf-8",
    )
    return launcher


def _write_uac_activation_launcher(
    runtime_root: Path,
    *,
    release_root: Path,
    python_executable: Path,
    metadata_path: Path,
) -> Path:
    launcher = runtime_root / "Activate-Desktop-Admin-Broker.cmd"
    uac_script = release_root / "scripts" / "desktop_admin_broker_uac_launcher.py"
    command = subprocess.list2cmdline(
        [
            str(python_executable),
            str(uac_script),
            "--metadata",
            str(metadata_path),
            "--confirm",
            "LAUNCH-DESKTOP-ADMIN-BROKER-UAC",
            "--timeout-seconds",
            "90",
        ]
    )
    launcher.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8")
    return launcher


def load_installed_metadata(metadata_path: Path, *, require_current_release: bool = False) -> dict[str, Any]:
    metadata_path = metadata_path.resolve()
    if not metadata_path.is_file():
        raise BrokerError("metadata do broker ausente")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    runtime_root = Path(str(metadata.get("runtime_root") or "")).resolve()
    release_root = Path(str(metadata.get("release_root") or "")).resolve()
    source_sha = validate_sha(str(metadata.get("source_sha") or ""))
    if metadata_path != runtime_root / "metadata.json":
        raise BrokerError("metadata fora do runtime governado")
    if os.name == "nt" and runtime_root != default_runtime_root().resolve():
        raise BrokerError("runtime_root fora do caminho governado")
    expected_release = runtime_root / "releases" / source_sha
    if release_root != expected_release:
        raise BrokerError("release_root não corresponde ao source_sha")
    release_broker = release_root / "scripts" / "desktop_admin_broker.py"
    launcher = runtime_root / "run.py"
    python_executable = Path(str(metadata.get("python_executable") or "")).resolve()
    for path in (release_broker, launcher, python_executable):
        if not path.is_file():
            raise BrokerError(f"arquivo instalado ausente: {path.name}")
    if require_current_release and release_broker.resolve() != Path(__file__).resolve():
        raise BrokerError("subcomando elevado deve executar da release imutável")
    return {
        "metadata": metadata,
        "metadata_path": metadata_path,
        "runtime_root": runtime_root,
        "release_root": release_root,
        "release_broker": release_broker,
        "launcher": launcher,
        "python_executable": python_executable,
    }


def persist_task_activation(
    metadata_path: Path,
    *,
    observed: dict[str, Any],
    started: dict[str, Any],
) -> dict[str, Any]:
    if not task_ready(observed):
        raise BrokerError("task_registration_readback_failed")
    lock_handle = _acquire_metadata_lock(metadata_path)
    try:
        latest = load_installed_metadata(
            metadata_path,
            require_current_release=False,
        )["metadata"]
        metadata = dict(latest)
        metadata.update(
            {
                "activation_pending": False,
                "requires_uac_activation": False,
                "admin_channel_ready": True,
                "admin_task": observed,
                "admin_task_start": started,
                "uac_activated_at": now_iso(),
            }
        )
        atomic_json(metadata_path, metadata)
    finally:
        _release_broker_lock(lock_handle)
    remove_user_autostart()
    return metadata


def register_task_from_metadata(metadata_path: Path) -> dict[str, Any]:
    installation = load_installed_metadata(metadata_path, require_current_release=True)
    register_task(
        python_executable=installation["python_executable"],
        launcher=installation["launcher"],
    )
    observed = task_status()
    ready = task_ready(observed)
    if not ready:
        raise BrokerError("task_registration_readback_failed")
    started = run_task()
    persist_task_activation(
        installation["metadata_path"],
        observed=observed,
        started=started,
    )
    return {"ok": True, "task": observed, "start": started, "metadata_updated": True}


def install(
    source_root: Path,
    *,
    source_sha: str,
    python_executable: Path,
    runtime_root: Path | None,
    poll_seconds: int,
    confirm: str,
) -> dict[str, Any]:
    if confirm != INSTALL_CONFIRM:
        raise BrokerError("confirmação inválida")
    host = require_windows_desktop()
    sha = validate_sha(source_sha)
    runtime = (runtime_root or default_runtime_root()).resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    persistent_python = stage_persistent_python(
        python_executable.resolve(),
        runtime,
    )
    stable_python = Path(persistent_python["python_executable"])
    release = runtime / "releases" / sha
    _copy_release(source_root.resolve(), release)
    launcher = _write_launcher(runtime)
    metadata_path = runtime / "metadata.json"
    activation_launcher = _write_uac_activation_launcher(
        runtime,
        release_root=release,
        python_executable=stable_python,
        metadata_path=metadata_path,
    )
    metadata = {
        "schema_version": "1",
        "service": "reqsys-desktop-admin-broker",
        "host": host,
        "source_sha": sha,
        "runtime_root": str(runtime),
        "release_root": str(release),
        "python_executable": str(stable_python),
        "python_runtime": {
            "persistent": True,
            "version": persistent_python["version"],
            "executable_sha256": persistent_python["executable_sha256"],
            "reused": persistent_python["reused"],
        },
        "poll_seconds": DEFAULT_POLL_SECONDS,
        "not_before": now_iso(),
        "repository": REPOSITORY,
        "issue_number": ISSUE_NUMBER,
        "expected_actor": EXPECTED_ACTOR,
        "activation_pending": False,
        "requires_uac_activation": False,
        "production_touched": False,
        "secrets_read": False,
        "installed_at": now_iso(),
        "activation_launcher": str(activation_launcher),
        "broker_supervisor_version": BROKER_SUPERVISOR_VERSION,
    }
    atomic_json(metadata_path, metadata)
    activation_pending = False
    user_autostart = None
    started = None
    try:
        task = register_task(python_executable=stable_python, launcher=launcher)
    except BrokerError as exc:
        if str(exc) != "task_scheduler_access_denied":
            raise
        activation_pending = True
        task = {"exists": False, "error": "access_denied"}
        user_autostart = register_user_autostart(
            python_executable=stable_python,
            launcher=launcher,
        )
        metadata.update(
            {
                "activation_pending": True,
                "requires_uac_activation": True,
                "fallback_persistence": user_autostart,
                "fallback_start_requested": True,
                "functional_success_proven": False,
            }
        )
        atomic_json(metadata_path, metadata)
        started = start_user_broker(
            python_executable=stable_python,
            launcher=launcher,
        )
    if not activation_pending:
        started = run_task()
    return {
        "ok": True,
        "activation_pending": activation_pending,
        "requires_uac_activation": activation_pending,
        "task": task,
        "user_autostart": user_autostart,
        "start": started,
        "functional_success_proven": False if activation_pending else None,
        "metadata_path": str(metadata_path),
        "activation_launcher": str(activation_launcher),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    install_p = sub.add_parser("install")
    install_p.add_argument("--source-root", type=Path, required=True)
    install_p.add_argument("--source-sha", required=True)
    install_p.add_argument("--python-executable", type=Path, default=Path(sys.executable))
    install_p.add_argument("--runtime-root", type=Path)
    install_p.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    install_p.add_argument("--confirm", required=True)

    watch_p = sub.add_parser("watch")
    watch_p.add_argument("--metadata", type=Path, required=True)

    once_p = sub.add_parser("once")
    once_p.add_argument("--metadata", type=Path, required=True)

    register_p = sub.add_parser("register-task-com")
    register_p.add_argument("--metadata", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "install":
            payload = install(
                args.source_root,
                source_sha=args.source_sha,
                python_executable=args.python_executable,
                runtime_root=args.runtime_root,
                poll_seconds=args.poll_seconds,
                confirm=args.confirm,
            )
        elif args.command == "watch":
            return watch(args.metadata.resolve())
        elif args.command == "once":
            metadata = load_installed_metadata(args.metadata.resolve())["metadata"]
            payload = process_once(metadata)
        else:
            payload = register_task_from_metadata(args.metadata.resolve())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:1000], "error_type": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
