from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "engineering_worker_pool_auth_reconcile_dev.py"

spec = importlib.util.spec_from_file_location("worker_pool_auth_reconcile", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _container() -> dict:
    return {
        "Image": "sha256:" + ("d" * 64),
        "Config": {
            "Labels": {"com.docker.compose.project": "reqsys"},
            "Env": [
                f"CODEX_WORKER_POOL_API_TOKEN_FILE={module.TOKEN_DESTINATION}",
                "CODEX_WORKER_POOL_EXPECTED_RULES_SHA=" + ("a" * 40),
            ],
        },
    }


def test_container_token_compare_never_places_secret_in_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[list[str], str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append((command, str(kwargs.get("input") or "")))
        return subprocess.CompletedProcess(command, 3, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    secret = "s" * 48
    assert module._container_token_matches_host("container-1", secret) is False

    command, stdin_value = seen[0]
    assert secret == stdin_value
    assert secret not in json.dumps(command)
    assert "-i" in command
    assert "exec" in command


def test_recreate_service_is_scoped_to_existing_image_and_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert module._compose_contract_valid() is True
    seen: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        assert failure_reason == "worker_pool_service_recreate_failed"
        seen.append((args, env))
        return ""

    monkeypatch.setattr(module, "_docker", fake_docker)
    token_path = Path("C:/secure/worker-pool-token")

    module._recreate_service(_container(), token_path)

    args, env = seen[0]
    assert args[-8:] == [
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--no-build",
        "--pull",
        "never",
        module.SERVICE,
    ]
    assert "--project-name" in args
    assert args[args.index("--project-name") + 1] == "reqsys"
    assert env is not None
    assert env["CODEX_WORKER_POOL_API_TOKEN_FILE_HOST"] == str(token_path)
    assert env["CODEX_WORKER_POOL_RUNNING_IMAGE"] == "sha256:" + ("d" * 64)
    assert env["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] == "a" * 40
    assert "s" * 48 not in json.dumps(args)
    assert "s" * 48 not in json.dumps(env)


def test_reconcile_recreates_only_when_401_and_bind_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 48, encoding="utf-8")
    container = _container()

    monkeypatch.setattr(
        module, "_canonical_context", lambda: ("container-1", token_file, container)
    )
    states = iter(
        [
            (False, "worker_pool_token_mismatch", 200, 401),
            (True, "", 200, 200),
        ]
    )
    monkeypatch.setattr(module, "_runtime_state", lambda _token: next(states))
    monkeypatch.setattr(
        module, "_container_token_matches_host", lambda _container_id, _token: False
    )
    recreated: list[Path] = []
    monkeypatch.setattr(
        module,
        "_recreate_service",
        lambda _container, path: recreated.append(path),
    )
    monkeypatch.setattr(module, "_wait_ready", lambda _token: (200, 200))

    result = module.reconcile()

    assert recreated == [token_file]
    assert result["existing_token_reused"] is True
    assert result["token_rotated"] is False
    assert result["service_recreated"] is True
    assert result["bind_mount_resynced"] is True
    assert result["authenticated_readback"] is True
    assert result["secret_value_exposed"] is False


def test_reconcile_fails_closed_when_process_rejects_matching_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 48, encoding="utf-8")
    container = _container()

    monkeypatch.setattr(
        module, "_canonical_context", lambda: ("container-1", token_file, container)
    )
    monkeypatch.setattr(
        module,
        "_runtime_state",
        lambda _token: (False, "worker_pool_token_mismatch", 200, 401),
    )
    monkeypatch.setattr(
        module, "_container_token_matches_host", lambda _container_id, _token: True
    )
    monkeypatch.setattr(
        module,
        "_recreate_service",
        lambda _container, _path: pytest.fail("must not recreate"),
    )

    with pytest.raises(module.ReconcileError, match="worker_pool_auth_process_mismatch"):
        module.reconcile()


def test_reconcile_is_idempotent_noop_when_runtime_is_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 48, encoding="utf-8")
    monkeypatch.setattr(
        module, "_canonical_context", lambda: ("container-1", token_file, _container())
    )
    monkeypatch.setattr(module, "_runtime_state", lambda _token: (True, "", 200, 200))
    monkeypatch.setattr(
        module,
        "_recreate_service",
        lambda _container, _path: pytest.fail("healthy runtime must remain untouched"),
    )

    result = module.reconcile()

    assert result["service_recreated"] is False
    assert result["bind_mount_resynced"] is False
    assert result["token_rotated"] is False
    assert result["authenticated_readback"] is True
