#!/usr/bin/env python3
"""Bootstrap governado de um runner dedicado ao Desktop PC24x7 Runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from pc24x7_host_policy import authorized_host

import desktop_control_plane_watchdog as watchdog

EXPECTED_HOST = "DESKTOP-PDQK954"  # compatibility default; runtime identity comes from host policy
EXPECTED_GITHUB_LOGIN = "ericson-j-santos"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
RUNNER_NAME = "DESKTOP-PDQK954-runtime"  # compatibility default; resolved per authorized host
RUNNER_LABELS = "pc24x7,desktop-runtime,runtime-dev,desktop-pdqk954"  # compatibility default; resolved per authorized host
REQUIRED_LABELS = ("self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime", "runtime-dev", "desktop-pdqk954")
CONFIRM = "BOOTSTRAP-DESKTOP-RUNTIME-RUNNER"
RUNNER_VERSION = "2.337.0"
RUNNER_ASSET_URL = (
    "https://github.com/actions/runner/releases/download/"
    f"v{RUNNER_VERSION}/actions-runner-win-x64-{RUNNER_VERSION}.zip"
)
RUNNER_ASSET_SHA256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"


class BootstrapError(RuntimeError):
    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state


def default_runner_home() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise BootstrapError("localappdata_missing", "LOCALAPPDATA não definido")
    return Path(local) / "DesktopPC24x7" / "GitHubRunner"


def validate_host() -> str:
    if os.name != "nt":
        raise BootstrapError("windows_required", "Windows obrigatório")
    host = socket.gethostname()
    try:
        profile = authorized_host(host)
    except ValueError as exc:
        raise BootstrapError("host_not_authorized", str(exc)) from None
    if profile.role not in {"desktop-primary", "desktop-secondary"}:
        raise BootstrapError("host_not_authorized", "runner desktop exige host desktop autorizado")
    if platform.machine().casefold() not in {"amd64", "x86_64"}:
        raise BootstrapError("x64_required", "arquitetura x64 obrigatória")
    return host


def find_gh() -> Path | None:
    located = shutil.which("gh")
    if located:
        return Path(located)
    candidates = (
        Path(os.environ.get("ProgramFiles") or r"C:\\Program Files") / "GitHub CLI" / "gh.exe",
        Path(os.environ.get("LOCALAPPDATA") or "") / "Programs" / "GitHub CLI" / "gh.exe",
    )
    return next((item for item in candidates if item.is_file()), None)


def gh_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    return env


def local_gh_api_json(path: str, *, method: str = "GET") -> dict[str, Any]:
    gh = find_gh()
    if gh is None:
        raise BootstrapError("github_local_auth_required", "GitHub CLI autenticado indisponível")
    env = gh_env()
    who = subprocess.run(
        [str(gh), "api", "user", "--jq", ".login"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=env,
    )
    if who.returncode != 0 or who.stdout.strip().casefold() != EXPECTED_GITHUB_LOGIN.casefold():
        raise BootstrapError("github_local_auth_required", "sessão GitHub local do owner não validada")
    completed = subprocess.run(
        [str(gh), "api", "--method", method, path.lstrip("/")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        raise BootstrapError("github_local_api_failed", "GitHub CLI local não autorizou o endpoint fixo")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise BootstrapError("github_api_invalid", "resposta GitHub local inválida") from None
    if not isinstance(payload, dict):
        raise BootstrapError("github_api_invalid", "resposta GitHub inválida")
    return payload


def api_json(path: str, *, method: str = "GET", token: str | None) -> dict[str, Any]:
    if token is None:
        return local_gh_api_json(path, method=method)
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Desktop-PC24x7-Runtime-Runner-Bootstrap/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise BootstrapError("github_api_failed", f"GitHub API falhou: HTTP {exc.code}") from None
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise BootstrapError("github_api_failed", f"GitHub API indisponível: {type(exc).__name__}") from None
    if not isinstance(payload, dict):
        raise BootstrapError("github_api_invalid", "resposta GitHub inválida")
    return payload


def registration_token(token: str | None) -> str:
    payload = api_json(
        f"/repos/{REPOSITORY}/actions/runners/registration-token",
        method="POST",
        token=token,
    )
    value = str(payload.get("token") or "")
    if len(value) < 20:
        raise BootstrapError("registration_token_missing", "token efêmero de registro não retornado")
    return value


def registry_snapshot(token: str | None) -> dict[str, Any]:
    payload = api_json(f"/repos/{REPOSITORY}/actions/runners?per_page=100", token=token)
    raw = payload.get("runners")
    if not isinstance(raw, list):
        raise BootstrapError("runner_registry_invalid", "lista de runners ausente")
    matches = [
        item for item in raw
        if isinstance(item, dict)
        and str(item.get("name") or "").casefold() == RUNNER_NAME.casefold()
    ]
    if not matches:
        return {"present": False, "id": None, "status": "missing", "busy": False, "labels": [], "labels_ok": False}
    if len(matches) != 1:
        raise BootstrapError("runner_registry_ambiguous", "mais de um runner dedicado com o mesmo nome")
    item = matches[0]
    labels_raw = item.get("labels")
    labels = sorted({
        str(label.get("name") or "")
        for label in labels_raw
        if isinstance(label, dict) and str(label.get("name") or "")
    }) if isinstance(labels_raw, list) else []
    observed = {label.casefold() for label in labels}
    required = {label.casefold() for label in REQUIRED_LABELS}
    return {
        "present": True,
        "id": item.get("id"),
        "status": str(item.get("status") or "unknown").casefold(),
        "busy": bool(item.get("busy")),
        "labels": labels,
        "labels_ok": required.issubset(observed),
    }


def runner_binary_contract(root: Path) -> bool:
    return (
        root.is_dir()
        and (root / "config.cmd").is_file()
        and (root / "run.cmd").is_file()
        and (root / "bin" / "Runner.Listener.exe").is_file()
    )


def runner_contract(root: Path) -> bool:
    return runner_binary_contract(root) and (root / ".runner").is_file()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract(zip_path: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            destination = (target / member.filename).resolve()
            if destination != root and root not in destination.parents:
                raise BootstrapError("runner_archive_invalid", "arquivo do runner contém caminho inválido")
        archive.extractall(target)


def ensure_runner_binaries(root: Path) -> None:
    if runner_binary_contract(root):
        return
    if root.exists() and any(root.iterdir()):
        raise BootstrapError("runner_home_not_empty", "diretório dedicado existe sem contrato válido")
    root.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        RUNNER_ASSET_URL,
        headers={"User-Agent": "Desktop-PC24x7-Runtime-Runner-Bootstrap/1.0"},
    )
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        archive = Path(handle.name)
    try:
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
        if sha256_file(archive).casefold() != RUNNER_ASSET_SHA256.casefold():
            raise BootstrapError("runner_digest_mismatch", "SHA-256 do runner oficial divergente")
        safe_extract(archive, root)
    finally:
        archive.unlink(missing_ok=True)
    if not runner_binary_contract(root):
        raise BootstrapError("runner_install_incomplete", "binários oficiais incompletos")


def run_config(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "cmd.exe"
    if not cmd.is_file():
        raise BootstrapError("cmd_required", "cmd.exe não encontrado")
    return subprocess.run(
        [str(cmd), "/d", "/s", "/c", subprocess.list2cmdline([str(root / "config.cmd"), *args])],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def register_runner(root: Path, token: str) -> None:
    ephemeral = registration_token(token)
    try:
        completed = run_config(
            root,
            [
                "--unattended",
                "--url", REPOSITORY_URL,
                "--token", ephemeral,
                "--name", RUNNER_NAME,
                "--labels", RUNNER_LABELS,
                "--work", "_work",
            ],
        )
    finally:
        ephemeral = ""
    if completed.returncode != 0 or not runner_contract(root):
        raise BootstrapError("runner_registration_failed", f"registro falhou: exit={completed.returncode}")


def wait_online(token: str | None, timeout_seconds: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    current = registry_snapshot(token)
    while time.monotonic() < deadline:
        if current.get("present") and current.get("status") == "online" and current.get("labels_ok"):
            return current
        if current.get("present") and not current.get("labels_ok"):
            return current
        time.sleep(2)
        current = registry_snapshot(token)
    return current


def persist(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def bootstrap(*, source_sha: str, evidence_file: Path | None = None) -> dict[str, Any]:
    host = validate_host()
    profile = authorized_host(host)
    global RUNNER_NAME, RUNNER_LABELS, REQUIRED_LABELS
    RUNNER_NAME = profile.runner_name
    RUNNER_LABELS = profile.runner_labels
    REQUIRED_LABELS = ("self-hosted", "Windows", "X64", *tuple(x for x in profile.runner_labels.split(",") if x))
    if len(source_sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in source_sha):
        raise BootstrapError("source_sha_invalid", "source_sha inválido")
    token = os.environ.get("GH_TOKEN", "").strip() or None
    credential_mode = "actions_secret" if token else "local_gh"
    root = default_runner_home().resolve()
    try:
        before = registry_snapshot(token)
    except BootstrapError as exc:
        if token is None or exc.state not in {"github_api_failed", "github_api_invalid"}:
            raise
        token = None
        credential_mode = "local_gh"
        before = registry_snapshot(None)
    local_before = runner_contract(root)

    if before.get("present") and not local_before:
        raise BootstrapError("remote_local_divergence", "registro remoto existe sem contrato local dedicado")
    if not local_before:
        ensure_runner_binaries(root)
        register_runner(root, token)

    started = watchdog.start_runner(root, root / "logs" / "runner.log")
    after = wait_online(token)
    local_running = watchdog.runner_running(root)
    ok = bool(local_running and after.get("present") and after.get("status") == "online" and after.get("labels_ok"))
    result = {
        "ok": ok,
        "state": "runner_ready" if ok else "runner_not_ready",
        "host": host,
        "repository": REPOSITORY,
        "source_sha": source_sha.lower(),
        "runner_name": RUNNER_NAME,
        "runner_home": str(root),
        "runner_labels": RUNNER_LABELS,
        "runner_local_contract_before": local_before,
        "runner_registered_now": not local_before,
        "runner_started_now": bool(started.get("started")),
        "runner_running": local_running,
        "registry_before": before,
        "registry_after": after,
        "github_credential_mode": credential_mode,
        "registration_token_consumed_in_memory": not local_before,
        "registration_token_persisted": False,
        "registration_token_logged": False,
        "production_touched": False,
        "reboot_performed": False,
        "existing_reqsys_runner_modified": False,
    }
    persist(evidence_file, result)
    return result


ORCHESTRATOR_PLAN_CONFIRM = "PLAN-ORCHESTRATOR-DEV-RUNNER"
ORCHESTRATOR_APPLY_CONFIRM = "REGISTER-ORCHESTRATOR-DEV-RUNNER"
ORCHESTRATOR_LABELS = "orchestrator-dev,desktop-pdqk954"


def _orchestrator_probe():
    import orchestrator_dev_runner_preflight as probe

    if Path(probe.__file__).resolve() != Path(__file__).with_name("orchestrator_dev_runner_preflight.py").resolve():
        raise BootstrapError("source_import_path_mismatch", "source_import_path_mismatch")
    return probe


def _orchestrator_readback(source_sha: str, correlation_id: str) -> dict[str, Any]:
    probe = _orchestrator_probe()
    try:
        return probe.preflight(
            expected_sha=source_sha,
            correlation_id=correlation_id,
            local_auth_only=True,
        )
    except probe.bootstrap.BootstrapError as exc:
        raise BootstrapError(exc.state, exc.state) from None


def _orchestrator_package_policy() -> dict[str, Any]:
    """Read official metadata only; this never downloads or executes a package."""
    from datetime import datetime, timezone
    from pc24x7_host_policy import (
        ORCHESTRATOR_DEV_RUNNER_PACKAGE as package,
        ORCHESTRATOR_DEV_RUNNER_PROFILE as profile,
    )

    release = local_gh_api_json(f"/repos/actions/runner/releases/tags/v{package['version']}")
    assets = release.get("assets")
    matches = [
        item for item in assets
        if isinstance(item, dict) and item.get("name") == package["filename"]
    ] if isinstance(assets, list) else []
    if (
        release.get("tag_name") != "v" + package["version"]
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or len(matches) != 1
        or matches[0].get("size") != package["size"]
        or matches[0].get("digest") != "sha256:" + package["sha256"]
        or matches[0].get("browser_download_url") != package["url"]
    ):
        raise BootstrapError("orchestrator_package_metadata_mismatch", "orchestrator_package_metadata_mismatch")
    deprecation = local_gh_api_json(
        f"/repos/{profile['repository']}/actions/runners/deprecations/{package['version']}"
    )
    if deprecation.get("runner_version") != package["version"]:
        raise BootstrapError("orchestrator_version_policy_invalid", "orchestrator_version_policy_invalid")
    now = datetime.now(timezone.utc)
    dates = {}
    for field in ("registration_deprecates_at", "runtime_deprecates_at"):
        if field not in deprecation:
            raise BootstrapError("orchestrator_version_policy_incomplete", "orchestrator_version_policy_incomplete")
        value = deprecation[field]
        if value is not None:
            try:
                if not isinstance(value, str):
                    raise ValueError
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed <= now:
                    raise ValueError
            except (ValueError, TypeError):
                raise BootstrapError("orchestrator_runner_version_not_supported", "orchestrator_runner_version_not_supported") from None
        dates[field] = value
    return {
        "selected_version": package["version"],
        "official_package_metadata_verified": True,
        "registration_version_supported": True,
        "deprecation_api_status": "ok",
        **dates,
    }


def orchestrator_dev_plan(*, source_sha: str, correlation_id: str) -> dict[str, Any]:
    from pc24x7_host_policy import (
        ORCHESTRATOR_DEV_RUNNER_PACKAGE as package,
        ORCHESTRATOR_DEV_RUNNER_PROFILE as profile,
        ORCHESTRATOR_DEV_RUNNER_REQUIRED_LABELS as labels,
        orchestrator_dev_runner_profile,
    )

    readback = _orchestrator_readback(source_sha, correlation_id)
    try:
        orchestrator_dev_runner_profile(validate_host())
    except ValueError:
        raise BootstrapError("orchestrator_runner_host_not_authorized", "orchestrator_runner_host_not_authorized") from None
    policy = _orchestrator_package_policy()
    plan = {
        "schema_version": 1,
        "kind": "orchestrator-dev-runner-registration-plan",
        "source_sha": source_sha,
        "correlation_id": correlation_id,
        "profile": dict(profile),
        "runner_home": readback["runner_home"],
        "required_labels": sorted(labels),
        "package": dict(package),
        "version_policy": policy,
        "registration_required": readback["registration_required"],
        "observed_runner_id": readback["observed_runner_id"],
        "administrative_effects": [
            "create_only_the_closed_orchestrator_runner_home",
            "download_and_verify_the_pinned_official_runner",
            "configure_one_repository_runner_using_ephemeral_registration_token",
            "official_runner_persists_its_own_runtime_credentials",
        ] if readback["registration_required"] else [],
        "listener_start_planned": False,
        "watchdog_change_planned": False,
        "windows_task_change_planned": False,
        "additional_cost_authorized_brl": 0,
        "runtime_runner_change_planned": False,
    }
    digest = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {
        **plan,
        "plan_sha256": digest,
        "ok": True,
        "state": "REGISTRATION_PLAN_READY_EXECUTION_PENDING",
        "read_only": True,
        "registration_token_requested": False,
        "registration_performed": False,
        "runner_started": False,
        "watchdog_changed": False,
        "runner_binary_version_proven": False,
        "physical_pickup_proven": False,
        "continuous_operation_proven": False,
    }


def _orchestrator_clean_env() -> dict[str, str]:
    excluded = {"gh_token", "github_token", "runner_perflog", "github_actions_runner_httptrace"}
    return {
        key: value for key, value in os.environ.items()
        if key.casefold() not in excluded
        and not key.casefold().startswith("actions_runner_input_")
    }


def _orchestrator_version_probe(root: Path) -> str:
    from pc24x7_host_policy import ORCHESTRATOR_DEV_RUNNER_PACKAGE as package

    listener = root / "bin" / "Runner.Listener.exe"
    completed = subprocess.run(
        [str(listener), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        env=_orchestrator_clean_env(),
    )
    if completed.returncode != 0 or completed.stdout.strip() != package["version"]:
        raise BootstrapError("orchestrator_runner_binary_version_mismatch", "orchestrator_runner_binary_version_mismatch")
    return package["version"]


def _orchestrator_registration_token() -> str:
    import re
    from datetime import datetime, timezone
    from pc24x7_host_policy import ORCHESTRATOR_DEV_RUNNER_PROFILE as profile

    payload = local_gh_api_json(
        f"/repos/{profile['repository']}/actions/runners/registration-token",
        method="POST",
    )
    token = payload.get("token")
    try:
        expires = datetime.fromisoformat(str(payload.get("expires_at") or "").replace("Z", "+00:00"))
        valid_expiry = expires.tzinfo is not None and expires > datetime.now(timezone.utc)
    except ValueError:
        valid_expiry = False
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token) is None or not valid_expiry:
        raise BootstrapError("orchestrator_registration_token_invalid", "orchestrator_registration_token_invalid")
    return token


def _orchestrator_configure(root: Path, token: str) -> None:
    from pc24x7_host_policy import ORCHESTRATOR_DEV_RUNNER_PROFILE as profile

    listener = root / "bin" / "Runner.Listener.exe"
    if not listener.is_file():
        raise BootstrapError("orchestrator_runner_listener_missing", "orchestrator_runner_listener_missing")
    env = _orchestrator_clean_env()
    env["ACTIONS_RUNNER_INPUT_TOKEN"] = token
    args = [
        str(listener), "configure",
        "--unattended",
        "--url", "https://github.com/" + profile["repository"],
        "--name", profile["runner_name"],
        "--labels", ORCHESTRATOR_LABELS,
        "--work", "_work",
    ]
    try:
        completed = subprocess.run(
            args,
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
            env=env,
        )
    finally:
        env.pop("ACTIONS_RUNNER_INPUT_TOKEN", None)
    if completed.returncode != 0:
        raise BootstrapError("orchestrator_registration_command_failed", "orchestrator_registration_command_failed")


class _OrchestratorApplyLock:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.handle = None

    def __enter__(self):
        import msvcrt

        probe = _orchestrator_probe()
        probe.checked_path(self.home.parent, directory=True, allow_missing_tail=True)
        self.home.parent.mkdir(parents=True, exist_ok=True)
        probe.checked_path(self.home.parent, directory=True)
        lock = self.home.parent / "runner-bootstrap.lock"
        present = probe.checked_path(lock, directory=False, allow_missing_tail=True)
        try:
            self.handle = lock.open("r+b" if present else "x+b")
            self.handle.seek(0, os.SEEK_END)
            if self.handle.tell() == 0:
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            if self.handle is not None:
                self.handle.close()
            raise BootstrapError("orchestrator_bootstrap_lock_unavailable", "orchestrator_bootstrap_lock_unavailable") from None
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        import msvcrt

        if self.handle is not None:
            try:
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                self.handle.close()
        return False


def _orchestrator_download_package(staging: Path) -> Path:
    from pc24x7_host_policy import ORCHESTRATOR_DEV_RUNNER_PACKAGE as package

    archive = staging / package["filename"]
    request = urllib.request.Request(
        package["url"],
        headers={"User-Agent": "Desktop-PC24x7-Orchestrator-Runner-Bootstrap/1.0"},
    )
    received = 0
    with urllib.request.urlopen(request, timeout=120) as response, archive.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > package["size"]:
                raise BootstrapError("orchestrator_package_size_mismatch", "orchestrator_package_size_mismatch")
            output.write(chunk)
    if received != package["size"] or sha256_file(archive) != package["sha256"]:
        raise BootstrapError("orchestrator_package_integrity_failed", "orchestrator_package_integrity_failed")
    extracted = staging / "package"
    safe_extract(archive, extracted)
    if not runner_binary_contract(extracted) or (extracted / ".runner").exists():
        raise BootstrapError("orchestrator_package_contract_invalid", "orchestrator_package_contract_invalid")
    return extracted


def _orchestrator_binary_manifest(
    root: Path, *, expected: dict[str, str] | None = None,
) -> dict[str, str]:
    """Hash the entire regular layout; reject unexpected paths before reading bytes."""
    import stat

    probe = _orchestrator_probe()
    kinds: dict[str, str] = {}
    files: dict[str, tuple[Path, Any]] = {}

    def inspect(directory: Path) -> None:
        # Validate each directory and its ancestors before descending.
        probe.checked_path(directory, directory=True)
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: entry.name)
        for child in children:
            path = Path(child.path)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise BootstrapError("orchestrator_package_link_rejected", "orchestrator_package_link_rejected")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                kinds[relative + "/"] = "directory"
                inspect(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise BootstrapError("orchestrator_package_link_rejected", "orchestrator_package_link_rejected")
                kinds[relative] = "file"
                files[relative] = (path, info)
            else:
                raise BootstrapError("orchestrator_package_entry_invalid", "orchestrator_package_entry_invalid")

    inspect(root)
    if expected is not None:
        expected_kinds = {
            relative: "directory" if value == "directory" else "file"
            for relative, value in expected.items()
        }
        if kinds != expected_kinds:
            raise BootstrapError("orchestrator_package_changed", "orchestrator_package_changed")

    result = {relative: kind for relative, kind in kinds.items() if kind == "directory"}
    for relative, (path, before) in sorted(files.items()):
        probe.checked_path(path, directory=False)
        digest = sha256_file(path)
        after = path.lstat()
        attributes = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if (
            any(getattr(before, field) != getattr(after, field) for field in attributes)
            or getattr(after, "st_file_attributes", 0) & 0x400
        ):
            raise BootstrapError("orchestrator_package_changed", "orchestrator_package_changed")
        result[relative] = digest
    return dict(sorted(result.items()))


def _orchestrator_verify_version_copy(
    package_root: Path, manifest: dict[str, str],
) -> str:
    # --version creates _diag before parsing command arguments in the official
    # runner. Execute an identical disposable copy, never the install payload.
    version_root = package_root.parent / "version-probe"
    shutil.copytree(package_root, version_root, symlinks=True)
    if _orchestrator_binary_manifest(version_root, expected=manifest) != manifest:
        raise BootstrapError("orchestrator_package_changed", "orchestrator_package_changed")
    version = _orchestrator_version_probe(version_root)
    if _orchestrator_binary_manifest(package_root, expected=manifest) != manifest:
        raise BootstrapError("orchestrator_package_changed", "orchestrator_package_changed")
    return version


def _orchestrator_install_package(
    package_root: Path, home: Path, *, progress: dict[str, Any],
) -> None:
    probe = _orchestrator_probe()
    present = probe.checked_path(home, directory=True, allow_missing_tail=True)
    if present:
        if any(home.iterdir()):
            raise BootstrapError("runner_home_not_empty", "runner_home_not_empty")
        home.rmdir()
    os.replace(package_root, home)
    # The effect already happened. Record it before any fallible readback.
    progress["package_installed"] = True
    probe.checked_path(home, directory=True)


def _orchestrator_pre_registration(
    *, home: Path, source_sha: str, manifest: dict[str, str],
) -> None:
    probe = _orchestrator_probe()
    probe.require_source(source_sha)
    from pc24x7_host_policy import orchestrator_dev_runner_profile

    orchestrator_dev_runner_profile(validate_host())
    if probe.runner_home() != home:
        raise BootstrapError("orchestrator_runner_home_changed", "orchestrator_runner_home_changed")
    if _orchestrator_binary_manifest(home, expected=manifest) != manifest:
        raise BootstrapError("orchestrator_package_changed", "orchestrator_package_changed")
    for name in (".runner", ".credentials", ".credentials_rsaparams", ".service", ".env", ".path"):
        if probe.checked_path(home / name, directory=False, allow_missing_tail=True):
            raise BootstrapError("orchestrator_registration_state_changed", "orchestrator_registration_state_changed")
    if probe.registry_snapshot(local_auth_only=True) is not None:
        raise BootstrapError("orchestrator_registration_state_changed", "orchestrator_registration_state_changed")
    probe.require_orchestrator()
    _orchestrator_package_policy()


def apply_orchestrator_dev_plan(
    *, source_sha: str, correlation_id: str, expected_plan_sha256: str, confirm: str,
) -> dict[str, Any]:
    import re

    progress = {
        "package_installed": False,
        "registration_token_requested": False,
        "registration_command_invoked": False,
        "registration_performed": False,
        "registered_runner_id": None,
        "runner_binary_version_proven": False,
    }
    fixed = {
        "kind": "orchestrator-dev-runner-registration",
        "source_sha": source_sha,
        "correlation_id": correlation_id,
        "read_only": False,
        "runner_started": False,
        "watchdog_changed": False,
        "windows_task_changed": False,
        "runtime_runner_modified": False,
        "physical_pickup_proven": False,
        "continuous_operation_proven": False,
        "registration_token_persisted": False,
        "registration_token_logged": False,
        "production_touched": False,
        "reboot_performed": False,
        "additional_cost_authorized_brl": 0,
    }
    try:
        if confirm != ORCHESTRATOR_APPLY_CONFIRM:
            raise BootstrapError("confirmation_invalid", "confirmation_invalid")
        if re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256 or "") is None:
            raise BootstrapError("orchestrator_plan_digest_invalid", "orchestrator_plan_digest_invalid")
        plan = orchestrator_dev_plan(source_sha=source_sha, correlation_id=correlation_id)
        if not plan["registration_required"]:
            return {
                **fixed, **progress,
                "ok": True,
                "state": "RUNNER_ALREADY_REGISTERED_ACTIVATION_PENDING",
                "registered_runner_id": plan["observed_runner_id"],
                "read_only": True,
                "plan_sha256": plan["plan_sha256"],
                "requested_plan_sha256": expected_plan_sha256,
                "no_mutation_required": True,
            }
        if plan["plan_sha256"] != expected_plan_sha256:
            raise BootstrapError("orchestrator_plan_changed", "orchestrator_plan_changed")
        home = Path(plan["runner_home"])
        with _OrchestratorApplyLock(home):
            locked = orchestrator_dev_plan(source_sha=source_sha, correlation_id=correlation_id)
            if locked["plan_sha256"] != expected_plan_sha256:
                raise BootstrapError("orchestrator_plan_changed", "orchestrator_plan_changed")
            with tempfile.TemporaryDirectory(prefix="runner-package-", dir=home.parent) as temporary:
                package_root = _orchestrator_download_package(Path(temporary))
                manifest = _orchestrator_binary_manifest(package_root)
                _orchestrator_verify_version_copy(package_root, manifest)
                progress["runner_binary_version_proven"] = True
                current = orchestrator_dev_plan(source_sha=source_sha, correlation_id=correlation_id)
                if current["plan_sha256"] != expected_plan_sha256:
                    raise BootstrapError("orchestrator_plan_changed", "orchestrator_plan_changed")
                _orchestrator_install_package(package_root, home, progress=progress)
            _orchestrator_pre_registration(home=home, source_sha=source_sha, manifest=manifest)
            progress["registration_token_requested"] = True
            token = _orchestrator_registration_token()
            try:
                progress["registration_command_invoked"] = True
                progress["registration_performed"] = None
                _orchestrator_configure(home, token)
            finally:
                token = ""
            readback = _orchestrator_readback(source_sha, correlation_id)
            runner_id = readback["observed_runner_id"]
            if readback["registration_required"] or type(runner_id) is not int or runner_id <= 0:
                raise BootstrapError("orchestrator_registration_readback_failed", "orchestrator_registration_readback_failed")
            progress["registration_performed"] = True
            progress["registered_runner_id"] = runner_id
        return {
            **fixed, **progress,
            "ok": True,
            "state": "RUNNER_REGISTERED_ACTIVATION_PENDING",
            "plan_sha256": expected_plan_sha256,
        }
    except Exception as exc:
        state = getattr(exc, "state", "")
        if not isinstance(state, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state) is None:
            state = "orchestrator_apply_failed"
        observed_id = None
        if progress["registration_command_invoked"]:
            try:
                remote = _orchestrator_probe().registry_snapshot(local_auth_only=True)
                if isinstance(remote, dict) and type(remote.get("id")) is int and remote["id"] > 0:
                    observed_id = remote["id"]
            except Exception:
                pass
        return {
            **fixed, **progress,
            "ok": False,
            "state": state,
            "partial_installation_preserved": progress["package_installed"],
            "observed_runner_id_after_failure": observed_id,
            "observed_id_creation_proven": False,
            "automatic_unregistration_performed": False,
        }


def _orchestrator_cli(args) -> int:
    if args.evidence_file is not None:
        print(json.dumps({"ok": False, "state": "orchestrator_stdout_evidence_only"}, sort_keys=True))
        return 2
    if not args.correlation_id:
        print(json.dumps({"ok": False, "state": "correlation_id_required"}, sort_keys=True))
        return 2
    if args.plan:
        if args.confirm != ORCHESTRATOR_PLAN_CONFIRM or args.expected_plan_sha256:
            print(json.dumps({"ok": False, "state": "confirmation_invalid"}, sort_keys=True))
            return 2
        try:
            result = orchestrator_dev_plan(
                source_sha=args.source_sha, correlation_id=args.correlation_id,
            )
        except Exception as exc:
            import re

            state = getattr(exc, "state", "")
            if not isinstance(state, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state) is None:
                state = "orchestrator_plan_failed"
            result = {
                "ok": False, "state": state, "read_only": True,
                "registration_token_requested": False,
                "registration_performed": False, "runner_started": False,
                "watchdog_changed": False,
            }
    elif args.apply:
        result = apply_orchestrator_dev_plan(
            source_sha=args.source_sha,
            correlation_id=args.correlation_id,
            expected_plan_sha256=args.expected_plan_sha256,
            confirm=args.confirm,
        )
    else:
        result = {"ok": False, "state": "orchestrator_explicit_mode_required"}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result.get("ok") else 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-file", type=Path)
    parser.add_argument("--target", choices=("runtime", "orchestrator-dev"), default="runtime")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--correlation-id")
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args()
    if args.target == "orchestrator-dev":
        return _orchestrator_cli(args)
    if args.plan or args.apply or args.correlation_id or args.expected_plan_sha256:
        print(json.dumps({"ok": False, "state": "runtime_extra_mode_rejected"}, sort_keys=True))
        return 2
    if args.confirm != CONFIRM:
        print(json.dumps({"ok": False, "state": "confirmation_invalid"}, sort_keys=True))
        return 2
    try:
        result = bootstrap(source_sha=args.source_sha, evidence_file=args.evidence_file)
    except BootstrapError as exc:
        result = {
            "ok": False,
            "state": exc.state,
            "error": str(exc)[:500],
            "registration_token_persisted": False,
            "registration_token_logged": False,
            "production_touched": False,
            "reboot_performed": False,
            "existing_reqsys_runner_modified": False,
        }
        persist(args.evidence_file, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 4
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
