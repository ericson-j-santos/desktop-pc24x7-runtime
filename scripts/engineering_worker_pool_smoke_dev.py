#!/usr/bin/env python3
"""Adaptador host-specific para smoke DEV do Engineering Worker Pool no Desktop.

Responsabilidades deste repositório:
- provar host/runner e SHA do runtime;
- localizar de forma fail-closed o bind mount local do token sem ler seu conteúdo;
- executar o harness versionado do engineering-worker-pool em SHA imutável;
- publicar somente evidência sanitizada.

A lógica funcional do Worker Pool permanece no repositório engineering-worker-pool.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_RUNNER = "DESKTOP-PDQK954-runtime"
POOL_URL = "http://127.0.0.1:8097"
POOL_SERVICE = "codex-worker-pool"
POOL_HOST_IP = "127.0.0.1"
POOL_HOST_PORT = "8097"
POOL_CONTAINER_PORT = "8097/tcp"
TOKEN_DESTINATION = "/run/secrets/codex_worker_pool_api_token"
AUTH_RECONCILE_SCRIPT = ROOT / "scripts" / "engineering_worker_pool_auth_reconcile_dev.py"


class RuntimeSmokeError(RuntimeError):
    pass


DockerRun = Callable[[list[str]], subprocess.CompletedProcess[str]]


def validate_sha(value: str, reason: str) -> str:
    normalized = value.strip().lower()
    if not SHA40.fullmatch(normalized):
        raise RuntimeSmokeError(reason)
    return normalized


def git_sha(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            text=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeSmokeError("git_sha_probe_failed") from exc
    return completed.stdout.strip().lower()


def validate_runtime_identity(env: dict[str, str] | None = None) -> None:
    source = os.environ if env is None else env
    if source.get("COMPUTERNAME", "").strip().upper() != EXPECTED_HOST:
        raise RuntimeSmokeError("unexpected_runtime_host")
    if source.get("RUNNER_NAME", "").strip() != EXPECTED_RUNNER:
        raise RuntimeSmokeError("unexpected_runtime_runner")


def _docker_run(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeSmokeError("worker_pool_docker_probe_failed") from exc


def _has_canonical_endpoint(container: dict[str, Any]) -> bool:
    labels = (container.get("Config") or {}).get("Labels") or {}
    if labels.get("com.docker.compose.service") != POOL_SERVICE:
        return False

    state = container.get("State") or {}
    if state.get("Running") is not True:
        return False

    ports = (container.get("NetworkSettings") or {}).get("Ports") or {}
    bindings = ports.get(POOL_CONTAINER_PORT) or []
    exact = [
        binding
        for binding in bindings
        if isinstance(binding, dict)
        and str(binding.get("HostIp") or "") == POOL_HOST_IP
        and str(binding.get("HostPort") or "") == POOL_HOST_PORT
    ]
    return len(exact) == 1


def discover_worker_pool_token_file(
    docker_run: DockerRun = _docker_run,
) -> Path:
    containers = docker_run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.service={POOL_SERVICE}",
            "--format",
            "{{.ID}}",
        ]
    )
    ids = list(
        dict.fromkeys(
            line.strip() for line in containers.stdout.splitlines() if line.strip()
        )
    )
    if not ids:
        raise RuntimeSmokeError("worker_pool_service_container_missing")

    inspected = docker_run(["docker", "inspect", *ids])
    try:
        payload = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeSmokeError("worker_pool_container_inspect_invalid") from exc

    if (
        not isinstance(payload, list)
        or len(payload) != len(ids)
        or any(not isinstance(item, dict) for item in payload)
    ):
        raise RuntimeSmokeError("worker_pool_container_inspect_invalid")

    candidates = [item for item in payload if _has_canonical_endpoint(item)]
    if len(candidates) != 1:
        raise RuntimeSmokeError("worker_pool_endpoint_container_not_unique")

    mounts = [
        mount
        for mount in candidates[0].get("Mounts") or []
        if isinstance(mount, dict)
        and mount.get("Type") == "bind"
        and mount.get("Destination") == TOKEN_DESTINATION
        and str(mount.get("Source") or "").strip()
    ]
    if len(mounts) != 1:
        raise RuntimeSmokeError("worker_pool_token_mount_not_unique")

    return Path(str(mounts[0]["Source"]))


def resolve_output_path(path: Path, base: Path | None = None) -> Path:
    if path.is_absolute():
        return path.resolve()
    root = Path.cwd() if base is None else base
    return (root / path).resolve()


def load_evidence(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeSmokeError("worker_pool_smoke_evidence_unavailable") from exc
    if not isinstance(payload, dict):
        raise RuntimeSmokeError("worker_pool_smoke_evidence_invalid")
    return payload


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_worker_pool_evidence(
    payload: dict[str, Any], expected_worker_pool_sha: str
) -> None:
    expected = {
        "result": "WORKER_POOL_SMOKE_PASSED",
        "expected_sha": expected_worker_pool_sha,
        "lane_enabled": False,
        "task_state": "queued",
        "leased_by": None,
        "replay_created": False,
        "independent_readback": True,
        "secrets_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeSmokeError(f"worker_pool_smoke_evidence_mismatch_{key}")


def invoke_worker_pool_harness(
    command: list[str], worker_pool_root: Path, child_evidence: Path
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    try:
        completed = subprocess.run(
            command,
            cwd=worker_pool_root,
            check=False,
            text=True,
            capture_output=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeSmokeError("worker_pool_smoke_process_failed") from exc
    return completed, load_evidence(child_evidence)


def run_auth_reconcile(output: Path) -> dict[str, Any]:
    if not AUTH_RECONCILE_SCRIPT.is_file():
        raise RuntimeSmokeError("worker_pool_auth_reconcile_script_missing")

    evidence = output.with_name("worker-pool-auth-reconcile.json")
    session_compose = Path.cwd() / "docker-compose.pc24x7-codex-worker-pool.yml"
    command = [
        sys.executable,
        str(AUTH_RECONCILE_SCRIPT),
        "--compose-file",
        str(session_compose),
        "--output",
        str(evidence),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
            timeout=150,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeSmokeError("worker_pool_auth_reconcile_process_failed") from exc

    payload = load_evidence(evidence)
    if completed.returncode != 0:
        reason = str(payload.get("reason") or "worker_pool_auth_reconcile_failed")
        raise RuntimeSmokeError(reason[:160])

    expected = {
        "result": "WORKER_POOL_AUTH_RECONCILE_PASSED",
        "existing_token_reused": True,
        "token_rotated": False,
        "authenticated_readback": True,
        "secret_value_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
        "reboot_executed": False,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeSmokeError(
                f"worker_pool_auth_reconcile_evidence_mismatch_{key}"
            )
    return payload


def run_runtime_smoke(
    *,
    expected_runtime_sha: str,
    expected_worker_pool_sha: str,
    worker_pool_root: Path,
    correlation_id: str,
    output: Path,
    env: dict[str, str] | None = None,
    docker_run: DockerRun = _docker_run,
) -> dict[str, Any]:
    expected_runtime_sha = validate_sha(
        expected_runtime_sha, "expected_runtime_sha_invalid"
    )
    expected_worker_pool_sha = validate_sha(
        expected_worker_pool_sha, "expected_worker_pool_sha_invalid"
    )
    if not correlation_id.strip():
        raise RuntimeSmokeError("correlation_id_invalid")

    validate_runtime_identity(env)

    if git_sha(ROOT) != expected_runtime_sha:
        raise RuntimeSmokeError("runtime_checkout_sha_mismatch")

    worker_pool_root = worker_pool_root.resolve()
    if git_sha(worker_pool_root) != expected_worker_pool_sha:
        raise RuntimeSmokeError("worker_pool_checkout_sha_mismatch")

    smoke_script = worker_pool_root / "scripts" / "worker_pool_smoke.py"
    if not smoke_script.is_file():
        raise RuntimeSmokeError("worker_pool_smoke_script_missing")

    token_file = discover_worker_pool_token_file(docker_run)
    if not token_file.is_file():
        raise RuntimeSmokeError("worker_pool_token_file_missing")

    output = resolve_output_path(output)
    child_evidence = output.with_name("worker-pool-evidence.json")
    command = [
        sys.executable,
        str(smoke_script),
        "--expected-sha",
        expected_worker_pool_sha,
        "--correlation-id",
        correlation_id,
        "--pool-url",
        POOL_URL,
        "--token-file",
        str(token_file),
        "--output",
        str(child_evidence),
    ]

    completed, payload = invoke_worker_pool_harness(
        command, worker_pool_root, child_evidence
    )
    auth_reconciled = False
    service_recreated = False
    smoke_attempts = 1

    if completed.returncode != 0:
        reason = str(payload.get("reason") or "worker_pool_smoke_failed")
        if reason != "worker_pool_http_401":
            raise RuntimeSmokeError(reason[:160])

        reconcile = run_auth_reconcile(output)
        auth_reconciled = True
        service_recreated = reconcile.get("service_recreated") is True
        smoke_attempts = 2

        completed, payload = invoke_worker_pool_harness(
            command, worker_pool_root, child_evidence
        )
        if completed.returncode != 0:
            retry_reason = str(payload.get("reason") or "worker_pool_smoke_failed")
            raise RuntimeSmokeError(retry_reason[:160])

    validate_worker_pool_evidence(payload, expected_worker_pool_sha)

    result = {
        "schema_version": "1.0.0",
        "result": "WORKER_POOL_RUNTIME_SMOKE_PASSED",
        "correlation_id": correlation_id,
        "host": EXPECTED_HOST,
        "runner": EXPECTED_RUNNER,
        "runtime_sha": expected_runtime_sha,
        "worker_pool_sha": expected_worker_pool_sha,
        "worker_pool_result": payload["result"],
        "task_id": payload.get("task_id"),
        "lane_enabled": payload["lane_enabled"],
        "task_state": payload["task_state"],
        "leased_by": payload["leased_by"],
        "replay_created": payload["replay_created"],
        "independent_readback": payload["independent_readback"],
        "auth_reconciled": auth_reconciled,
        "service_recreated": service_recreated,
        "smoke_attempts": smoke_attempts,
        "token_path_exposed": False,
        "secrets_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
        "reboot_executed": False,
    }
    write_evidence(output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Executa smoke DEV do Engineering Worker Pool no Desktop runtime"
    )
    parser.add_argument("--expected-runtime-sha", required=True)
    parser.add_argument("--expected-worker-pool-sha", required=True)
    parser.add_argument("--worker-pool-root", type=Path, required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/engineering-worker-pool-smoke/evidence.json"),
    )
    args = parser.parse_args()

    try:
        result = run_runtime_smoke(
            expected_runtime_sha=args.expected_runtime_sha,
            expected_worker_pool_sha=args.expected_worker_pool_sha,
            worker_pool_root=args.worker_pool_root,
            correlation_id=args.correlation_id,
            output=args.output,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except RuntimeSmokeError as exc:
        blocked = {
            "schema_version": "1.0.0",
            "result": "WORKER_POOL_RUNTIME_SMOKE_BLOCKED",
            "reason": str(exc)[:160],
            "token_path_exposed": False,
            "secrets_exposed": False,
            "production_touched": False,
            "deploy_executed": False,
            "reboot_executed": False,
        }
        write_evidence(resolve_output_path(args.output), blocked)
        print(json.dumps(blocked, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
