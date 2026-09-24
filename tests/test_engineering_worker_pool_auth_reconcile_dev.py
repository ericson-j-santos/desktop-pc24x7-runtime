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

    image_id = "sha256:" + ("d" * 64)
    expected_ref = "desktop-pc24x7-worker-pool-recovery:sha256-" + ("d" * 64)

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        if args[:2] == ["image", "tag"]:
            assert failure_reason == "worker_pool_image_tag_failed"
            assert args == ["image", "tag", "d" * 64, expected_ref]
            return ""
        if args[:2] == ["image", "inspect"]:
            assert failure_reason == "worker_pool_image_tag_readback_failed"
            assert args == ["image", "inspect", expected_ref, "--format", "{{.Id}}"]
            return image_id + "\n"
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
    assert env["CODEX_WORKER_POOL_RUNNING_IMAGE"] == expected_ref
    assert env["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] == "a" * 40


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (
            "Error response from daemon: No such image: sha256:abc",
            "worker_pool_compose_image_unavailable",
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
        (
            "invalid reference format",
            "worker_pool_compose_image_reference_invalid",
        ),
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


def test_compose_image_reference_tags_exact_image_id_and_validates_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_id = "sha256:" + ("e" * 64)
    expected_ref = "desktop-pc24x7-worker-pool-recovery:sha256-" + ("e" * 64)
    calls: list[tuple[list[str], str]] = []

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        calls.append((args, failure_reason))
        if args[:2] == ["image", "inspect"]:
            return image_id + "\n"
        return ""

    monkeypatch.setattr(module, "_docker", fake_docker)

    container = _container()
    container["Image"] = image_id
    actual = module._compose_image_reference(container)

    assert actual == expected_ref
    assert calls == [
        (
            ["image", "tag", "e" * 64, expected_ref],
            "worker_pool_image_tag_failed",
        ),
        (
            ["image", "inspect", expected_ref, "--format", "{{.Id}}"],
            "worker_pool_image_tag_readback_failed",
        ),
    ]


def test_compose_image_reference_fails_closed_on_readback_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_id = "sha256:" + ("f" * 64)

    def fake_docker(
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        failure_reason: str = "worker_pool_docker_command_failed",
    ) -> str:
        if args[:2] == ["image", "inspect"]:
            return "sha256:" + ("a" * 64)
        return ""

    monkeypatch.setattr(module, "_docker", fake_docker)
    container = _container()
    container["Image"] = image_id

    with pytest.raises(
        module.ReconcileError,
        match="worker_pool_image_tag_readback_mismatch",
    ):
        module._compose_image_reference(container)


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
