#!/usr/bin/env python3
"""Reconcilia, sem rotação, o bind mount de autenticação do Worker Pool DEV."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
IMAGE_OVERRIDE_FILE = ROOT / "runtime" / "engineering-worker-pool-running-image.override.yml"
CANONICAL_COMPOSE_BASENAME = "docker-compose.pc24x7-codex-worker-pool.yml"
SERVICE = "codex-worker-pool"
CONTAINER_PORT = "8097/tcp"
HOST_IP = "127.0.0.1"
HOST_PORT = "8097"
TOKEN_DESTINATION = "/run/secrets/codex_worker_pool_api_token"
HEALTH_URL = "http://127.0.0.1:8097/health"
SNAPSHOT_URL = "http://127.0.0.1:8097/v1/snapshot"
MIN_TOKEN_LENGTH = 32
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ReconcileError(RuntimeError):
    pass


def _compose_failure_reason(stderr: str) -> str:
    normalized = stderr.casefold()
    classifications = (
        (
            "worker_pool_compose_image_unavailable",
            ("no such image", "pull access denied", "unable to get image"),
        ),
        (
            "worker_pool_compose_bind_source_unavailable",
            (
                "bind source path does not exist",
                "invalid mount config",
                "path is not shared",
                "file sharing",
            ),
        ),
        (
            "worker_pool_compose_port_conflict",
            ("port is already allocated", "address already in use"),
        ),
        (
            "worker_pool_compose_configuration_invalid",
            (
                "required variable",
                "is missing a value",
                "invalid interpolation format",
                "validating ",
            ),
        ),
        (
            "worker_pool_docker_permission_denied",
            ("permission denied", "access is denied"),
        ),
    )
    for reason, markers in classifications:
        if any(marker in normalized for marker in markers):
            return reason
    return "worker_pool_service_recreate_failed"


def _docker(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    failure_reason: str = "worker_pool_docker_command_failed",
) -> str:
    try:
        completed = subprocess.run(
            ["docker", *args],
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout,
            cwd=ROOT,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        reason = failure_reason
        if failure_reason == "worker_pool_service_recreate_failed":
            reason = _compose_failure_reason(exc.stderr or "")
        raise ReconcileError(reason) from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReconcileError(failure_reason) from exc
    return completed.stdout


def _http_get(url: str, token: str | None = None) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, method="GET", headers=headers)
    try:
        with urlopen(request, timeout=3) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
            return int(response.status), payload if isinstance(payload, dict) else {}
    except HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        return int(exc.code), payload if isinstance(payload, dict) else {}
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        return 0, {}


def _canonical_context() -> tuple[str, Path, dict[str, Any]]:
    raw_ids = _docker(
        [
            "ps",
            "--filter",
            f"label=com.docker.compose.service={SERVICE}",
            "--format",
            "{{.ID}}",
        ]
    )
    ids = list(
        dict.fromkeys(line.strip() for line in raw_ids.splitlines() if line.strip())
    )
    if not ids:
        raise ReconcileError("worker_pool_service_container_missing")

    try:
        inspected = json.loads(_docker(["inspect", *ids]))
    except json.JSONDecodeError as exc:
        raise ReconcileError("worker_pool_container_inspect_invalid") from exc

    candidates: list[tuple[str, Path, dict[str, Any]]] = []
    for container in inspected if isinstance(inspected, list) else []:
        if not isinstance(container, dict):
            continue
        labels = (container.get("Config") or {}).get("Labels") or {}
        if labels.get("com.docker.compose.service") != SERVICE:
            continue
        if (container.get("State") or {}).get("Running") is not True:
            continue
        bindings = ((container.get("NetworkSettings") or {}).get("Ports") or {}).get(
            CONTAINER_PORT
        ) or []
        exact_bindings = [
            item
            for item in bindings
            if isinstance(item, dict)
            and item.get("HostIp") == HOST_IP
            and item.get("HostPort") == HOST_PORT
        ]
        if len(exact_bindings) != 1:
            continue
        mounts = [
            mount
            for mount in container.get("Mounts") or []
            if isinstance(mount, dict)
            and mount.get("Type") == "bind"
            and mount.get("Destination") == TOKEN_DESTINATION
            and str(mount.get("Source") or "").strip()
        ]
        if len(mounts) != 1:
            continue
        container_id = str(container.get("Id") or "").strip()
        if not container_id:
            continue
        candidates.append(
            (container_id, Path(str(mounts[0]["Source"])), container)
        )

    if len(candidates) != 1:
        raise ReconcileError("worker_pool_endpoint_container_not_unique")
    return candidates[0]


def _read_host_token(path: Path) -> str:
    if not path.is_file():
        raise ReconcileError("worker_pool_token_file_missing")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except PermissionError as exc:
        raise ReconcileError("worker_pool_token_permission_denied") from exc
    except OSError as exc:
        raise ReconcileError("worker_pool_token_unavailable") from exc
    if len(token) < MIN_TOKEN_LENGTH:
        raise ReconcileError("worker_pool_token_invalid")
    return token


def _validate_container_contract(container: dict[str, Any]) -> None:
    env_entries = (container.get("Config") or {}).get("Env") or []
    expected = f"CODEX_WORKER_POOL_API_TOKEN_FILE={TOKEN_DESTINATION}"
    if expected not in env_entries:
        raise ReconcileError("worker_pool_token_env_mismatch")


def _container_token_matches_host(container_id: str, host_token: str) -> bool:
    script = (
        "from pathlib import Path; import hmac,sys; "
        f"actual=Path({TOKEN_DESTINATION!r}).read_text(encoding='utf-8').strip(); "
        "expected=sys.stdin.read().strip(); "
        "raise SystemExit(0 if hmac.compare_digest(actual, expected) else 3)"
    )
    try:
        completed = subprocess.run(
            ["docker", "exec", "-i", container_id, "python", "-c", script],
            input=host_token,
            text=True,
            capture_output=True,
            timeout=20,
            cwd=ROOT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReconcileError("worker_pool_container_token_compare_failed") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 3:
        return False
    raise ReconcileError("worker_pool_container_token_compare_failed")


def _runtime_state(token: str) -> tuple[bool, str, int, int]:
    health_status, health = _http_get(HEALTH_URL)
    snapshot_status, _snapshot = _http_get(SNAPSHOT_URL, token)
    healthy = (
        health_status == 200
        and health.get("status") == "healthy"
        and health.get("auth_configured") is True
        and health.get("expected_rules_sha_configured") is True
        and snapshot_status == 200
    )
    if healthy:
        return True, "", health_status, snapshot_status
    if health_status == 0:
        reason = "worker_pool_health_unreachable"
    elif health.get("auth_configured") is False:
        reason = "worker_pool_auth_file_not_visible_in_container"
    elif health.get("expected_rules_sha_configured") is False:
        reason = "worker_pool_expected_rules_sha_not_configured"
    elif snapshot_status == 401:
        reason = "worker_pool_token_mismatch"
    elif snapshot_status == 0:
        reason = "worker_pool_authenticated_endpoint_unreachable"
    else:
        reason = "worker_pool_runtime_not_ready"
    return False, reason, health_status, snapshot_status


def _running_image(container: dict[str, Any]) -> str:
    image = str(container.get("Image") or "").strip().lower()
    if not image.startswith("sha256:"):
        raise ReconcileError("worker_pool_running_image_invalid")
    digest = image.removeprefix("sha256:")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ReconcileError("worker_pool_running_image_invalid")
    return image


def _rules_sha(container: dict[str, Any]) -> str:
    for item in (container.get("Config") or {}).get("Env") or []:
        if isinstance(item, str) and item.startswith(
            "CODEX_WORKER_POOL_EXPECTED_RULES_SHA="
        ):
            value = item.split("=", 1)[1].strip().lower()
            if SHA40.fullmatch(value):
                return value
    raise ReconcileError("worker_pool_expected_rules_sha_not_configured")


def _canonical_compose_contract_valid(path: Path) -> bool:
    if path.name != CANONICAL_COMPOSE_BASENAME:
        return False
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return False
    required = (
        "codex-worker-pool:",
        '127.0.0.1:8097:8097',
        f"CODEX_WORKER_POOL_API_TOKEN_FILE: {TOKEN_DESTINATION}",
        "CODEX_WORKER_POOL_API_TOKEN_FILE_HOST",
        f":{TOKEN_DESTINATION}:ro",
        "CODEX_WORKER_POOL_EXPECTED_RULES_SHA",
        "codex-worker-pool-state:/data",
        "restart: unless-stopped",
    )
    return all(fragment in raw for fragment in required)


def _image_override_contract_valid() -> bool:
    try:
        raw = IMAGE_OVERRIDE_FILE.read_text(encoding="utf-8")
    except OSError:
        return False
    required = (
        "codex-worker-pool:",
        "CODEX_WORKER_POOL_RUNNING_IMAGE",
    )
    return all(fragment in raw for fragment in required)


def _recreate_service(
    container: dict[str, Any], token_path: Path, canonical_compose: Path
) -> None:
    canonical_compose = canonical_compose.resolve()
    if (
        not canonical_compose.is_file()
        or not _canonical_compose_contract_valid(canonical_compose)
    ):
        raise ReconcileError("worker_pool_canonical_compose_invalid")
    if not IMAGE_OVERRIDE_FILE.is_file() or not _image_override_contract_valid():
        raise ReconcileError("worker_pool_image_override_invalid")

    labels = (container.get("Config") or {}).get("Labels") or {}
    project = str(labels.get("com.docker.compose.project") or "").strip()
    if not project:
        raise ReconcileError("worker_pool_compose_identity_missing")

    process_env = os.environ.copy()
    process_env["CODEX_WORKER_POOL_API_TOKEN_FILE_HOST"] = str(token_path)
    process_env["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] = _rules_sha(container)
    process_env["CODEX_WORKER_POOL_RUNNING_IMAGE"] = _running_image(container)

    _docker(
        [
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(canonical_compose.parent),
            "--file",
            str(canonical_compose),
            "--file",
            str(IMAGE_OVERRIDE_FILE),
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            SERVICE,
        ],
        env=process_env,
        timeout=120,
        failure_reason="worker_pool_service_recreate_failed",
    )


def _wait_ready(token: str, attempts: int = 15) -> tuple[int, int]:
    last_health = 0
    last_snapshot = 0
    last_reason = "worker_pool_runtime_not_ready_after_recreate"
    for _ in range(attempts):
        healthy, reason, last_health, last_snapshot = _runtime_state(token)
        if healthy:
            return last_health, last_snapshot
        last_reason = reason or last_reason
        time.sleep(2)
    raise ReconcileError(last_reason)


def reconcile(canonical_compose: Path) -> dict[str, Any]:
    container_id, token_path, container = _canonical_context()
    _validate_container_contract(container)
    token = _read_host_token(token_path)

    healthy, reason, health_status, snapshot_status = _runtime_state(token)
    if healthy:
        return {
            "schema_version": "1.0.0",
            "result": "WORKER_POOL_AUTH_RECONCILE_PASSED",
            "existing_token_reused": True,
            "token_rotated": False,
            "service_recreated": False,
            "bind_mount_resynced": False,
            "authenticated_readback": True,
            "health_http_status": health_status,
            "snapshot_http_status": snapshot_status,
            "secret_value_exposed": False,
            "production_touched": False,
            "deploy_executed": False,
            "reboot_executed": False,
        }

    if reason != "worker_pool_token_mismatch":
        raise ReconcileError(reason or "worker_pool_runtime_not_ready")
    if _container_token_matches_host(container_id, token):
        raise ReconcileError("worker_pool_auth_process_mismatch")

    _recreate_service(container, token_path, canonical_compose)
    health_status, snapshot_status = _wait_ready(token)

    healthy, final_reason, _, _ = _runtime_state(token)
    if not healthy:
        raise ReconcileError(
            final_reason or "worker_pool_authenticated_readback_failed"
        )

    return {
        "schema_version": "1.0.0",
        "result": "WORKER_POOL_AUTH_RECONCILE_PASSED",
        "existing_token_reused": True,
        "token_rotated": False,
        "service_recreated": True,
        "bind_mount_resynced": True,
        "authenticated_readback": True,
        "health_http_status": health_status,
        "snapshot_http_status": snapshot_status,
        "secret_value_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
        "reboot_executed": False,
    }


def _write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconcilia bind mount de auth do Worker Pool DEV sem rotacionar segredo"
    )
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/engineering-worker-pool-smoke/auth-reconcile.json"),
    )
    args = parser.parse_args()
    try:
        result = reconcile(args.compose_file)
        _write_evidence(args.output, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except ReconcileError as exc:
        blocked = {
            "schema_version": "1.0.0",
            "result": "WORKER_POOL_AUTH_RECONCILE_BLOCKED",
            "reason": str(exc)[:160],
            "existing_token_reused": False,
            "token_rotated": False,
            "service_recreated": False,
            "bind_mount_resynced": False,
            "authenticated_readback": False,
            "secret_value_exposed": False,
            "production_touched": False,
            "deploy_executed": False,
            "reboot_executed": False,
        }
        _write_evidence(args.output, blocked)
        print(json.dumps(blocked, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
