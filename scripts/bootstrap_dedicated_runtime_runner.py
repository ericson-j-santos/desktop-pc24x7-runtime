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

import desktop_control_plane_watchdog as watchdog

EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_GITHUB_LOGIN = "ericson-j-santos"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
RUNNER_NAME = "DESKTOP-PDQK954-runtime"
RUNNER_LABELS = "pc24x7,desktop-runtime,runtime-dev"
REQUIRED_LABELS = ("self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime", "runtime-dev")
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
    return Path(local) / "DesktopPC24x7Runtime" / "GitHubRunner"


def validate_host() -> str:
    if os.name != "nt":
        raise BootstrapError("windows_required", "Windows obrigatório")
    host = socket.gethostname()
    if host.casefold() != EXPECTED_HOST.casefold():
        raise BootstrapError("host_not_authorized", f"host não autorizado: {host}")
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
        return {"present": False, "status": "missing", "busy": False, "labels": [], "labels_ok": False}
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()
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
