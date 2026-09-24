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
            "Image": "reqsys-codex-worker-pool:local",
            "Labels": {"com.docker.compose.project": "reqsys"},
            "Env": [
                f"CODEX_WORKER_POOL_API_TOKEN_FILE={module.TOKEN_DESTINATION}",
                "CODEX_WORKER_POOL_EXPECTED_RULES_SHA=" + ("a" * 40),
            ],
        },
    }


def _canonical_compose(tmp_path: Path) -> Path:
    path = tmp_path / module.CANONICAL_COMPOSE_BASENAME
    path.write_text(
        "\n".join(
            [
                "services:",
                "  codex-worker-pool:",
                "    build:",
                "      context: ./services/codex-worker-pool",
                "    restart: unless-stopped",
                '    ports: ["127.0.0.1:8097:8097"]',
                "    environment:",
                f"      CODEX_WORKER_POOL_API_TOKEN_FILE: {module.TOKEN_DESTINATION}",
                "      CODEX_WORKER_POOL_EXPECTED_RULES_SHA: x",
                "    volumes:",
                "      - codex-worker-pool-state:/data",
                f'      - "${{CODEX_WORKER_POOL_API_TOKEN_FILE_HOST}}:{module.TOKEN_DESTINATION}:ro"',
                "volumes:",
                "  codex-worker-pool-state:",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


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


def test_canonical_compose_contract_is_fail_closed(tmp_path: Path) -> None:
    canonical = _canonical_compose(tmp_path)
    assert module._canonical_compose_contract_valid(canonical) is True

    wrong_name = tmp_path / "other-compose.yml"
    wrong_name.write_text(canonical.read_text(encoding="utf-8"), encoding="utf-8")
    assert module._canonical_compose_contract_valid(wrong_name) is False

    canonical.write_text("services: {}\n", encoding="utf-8")
    assert module._canonical_compose_contract_valid(canonical) is False


def test_image_override_is_minimal_and_valid() -> None:
    assert module._image_override_contract_valid() is True
    raw = module.IMAGE_OVERRIDE_FILE.read_text(encoding="utf-8")
    assert "CODEX_WORKER_POOL_RUNNING_IMAGE" in raw
    assert "CODEX_WORKER_POOL_API_TOKEN_FILE_HOST" not in raw
    assert "volumes:" not in raw


def test_recreate_service_uses_canonical_compose_and_immutable_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = _canonical_compose(tmp_path)
    seen: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        if args[:3] == ["image", "inspect", "--format"]:
            assert failure_reason == "worker_pool_running_image_reference_missing"
            assert args[-1] == "reqsys-codex-worker-pool:local"
            return "sha256:" + ("d" * 64) + "\n"
        assert failure_reason == "worker_pool_service_recreate_failed"
        seen.append((args, env))
        return ""

    monkeypatch.setattr(module, "_docker", fake_docker)
    token_path = Path("C:/secure/worker-pool-token")

    module._recreate_service(_container(), token_path, canonical)

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
    assert args.count("--file") == 2
    first_index = args.index("--file")
    second_index = args.index("--file", first_index + 1)
    assert Path(args[first_index + 1]) == canonical.resolve()
    assert Path(args[second_index + 1]) == module.IMAGE_OVERRIDE_FILE
    assert args[args.index("--project-directory") + 1] == str(canonical.parent.resolve())
    assert args[args.index("--project-name") + 1] == "reqsys"

    assert env is not None
    assert env["CODEX_WORKER_POOL_API_TOKEN_FILE_HOST"] == str(token_path)
    assert env["CODEX_WORKER_POOL_RUNNING_IMAGE"] == "reqsys-codex-worker-pool:local"
    assert env["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] == "a" * 40


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (
            "Error response from daemon: No such image: sha256:abc",
            "worker_pool_compose_image_unavailable",
        ),
        (
            "invalid reference format",
            "worker_pool_compose_image_reference_invalid",
        ),
        (
            "invalid repository name (abc), cannot specify 64-byte hexadecimal strings",
            "worker_pool_compose_image_reference_invalid",
        ),
        (
            "unknown flag: --pull",
            "worker_pool_compose_cli_unsupported",
        ),
        (
            "invalid mount config for type bind",
            "worker_pool_compose_bind_source_unavailable",
        ),
        (
            "Bind source path does not exist: C:/missing",
            "worker_pool_compose_bind_source_unavailable",
        ),
        ("port is already allocated", "worker_pool_compose_port_conflict"),
        (
            "required variable CODEX_WORKER_POOL_EXPECTED_RULES_SHA is missing a value",
            "worker_pool_compose_configuration_invalid",
        ),
        ("Access is denied", "worker_pool_docker_permission_denied"),
        ("unexpected compose failure", "worker_pool_service_recreate_failed"),
    ],
)
def test_compose_failure_reason_is_specific_and_sanitized(
    stderr: str, expected: str
) -> None:
    assert module._compose_failure_reason(stderr) == expected


def test_docker_uses_sanitized_compose_failure_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "secret-value-must-not-leak"

    def fail(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["docker", "compose"],
            stderr=f"invalid mount config for type bind: {secret}",
        )

    monkeypatch.setattr(module.subprocess, "run", fail)

    with pytest.raises(
        module.ReconcileError, match="worker_pool_compose_bind_source_unavailable"
    ) as exc:
        module._docker(
            ["compose", "up"],
            failure_reason="worker_pool_service_recreate_failed",
        )

    assert secret not in str(exc.value)



def test_running_image_reference_must_resolve_to_exact_image_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        seen.append(args)
        return "sha256:" + ("d" * 64) + "\n"

    monkeypatch.setattr(module, "_docker", fake_docker)
    container = _container()
    image_id = module._running_image_id(container)
    image_ref = module._running_image_reference(container)
    module._verify_running_image_reference(image_ref, image_id)

    assert image_ref == "reqsys-codex-worker-pool:local"
    assert seen == [
        [
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "reqsys-codex-worker-pool:local",
        ]
    ]


def test_running_image_reference_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "_docker",
        lambda *_args, **_kwargs: "sha256:" + ("e" * 64) + "\n",
    )
    with pytest.raises(
        module.ReconcileError, match="worker_pool_running_image_reference_mismatch"
    ):
        module._verify_running_image_reference(
            "reqsys-codex-worker-pool:local", "sha256:" + ("d" * 64)
        )

def test_reconcile_recreates_only_when_401_and_bind_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 48, encoding="utf-8")
    canonical = _canonical_compose(tmp_path)
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
    recreated: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        module,
        "_recreate_service",
        lambda _container, path, compose: recreated.append((path, compose)),
    )
    monkeypatch.setattr(module, "_wait_ready", lambda _token: (200, 200))

    result = module.reconcile(canonical)

    assert recreated == [(token_file, canonical)]
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
    canonical = _canonical_compose(tmp_path)
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
        lambda _container, _path, _compose: pytest.fail("must not recreate"),
    )

    with pytest.raises(module.ReconcileError, match="worker_pool_auth_process_mismatch"):
        module.reconcile(canonical)


def test_reconcile_is_idempotent_noop_when_runtime_is_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 48, encoding="utf-8")
    canonical = _canonical_compose(tmp_path)
    monkeypatch.setattr(
        module, "_canonical_context", lambda: ("container-1", token_file, _container())
    )
    monkeypatch.setattr(module, "_runtime_state", lambda _token: (True, "", 200, 200))
    monkeypatch.setattr(
        module,
        "_recreate_service",
        lambda _container, _path, _compose: pytest.fail(
            "healthy runtime must remain untouched"
        ),
    )

    result = module.reconcile(canonical)

    assert result["service_recreated"] is False
    assert result["bind_mount_resynced"] is False
    assert result["token_rotated"] is False
    assert result["authenticated_readback"] is True
