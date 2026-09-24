from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import engineering_worker_pool_smoke_dev as smoke


RUNTIME_SHA = "a" * 40
WORKER_SHA = "b" * 40


def _completed(args: list[str], stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=0, stdout=stdout, stderr="")


def _container(
    *,
    container_id: str = "container-one",
    running: bool = True,
    mounts: list[dict] | None = None,
) -> dict:
    return {
        "Id": container_id,
        "Config": {
            "Labels": {"com.docker.compose.service": smoke.POOL_SERVICE},
            "Env": [],
        },
        "State": {"Running": running},
        "NetworkSettings": {
            "Ports": {
                smoke.POOL_CONTAINER_PORT: [
                    {"HostIp": smoke.POOL_HOST_IP, "HostPort": smoke.POOL_HOST_PORT}
                ]
            }
        },
        "Mounts": mounts
        if mounts is not None
        else [
            {
                "Type": "bind",
                "Source": "C:/secure/worker-pool-token",
                "Destination": smoke.TOKEN_DESTINATION,
            }
        ],
    }


def test_discover_token_file_requires_unique_canonical_container() -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            return _completed(args, "one\ntwo\n")
        return _completed(args, json.dumps([_container(), _container()]))

    with pytest.raises(
        smoke.RuntimeSmokeError, match="worker_pool_endpoint_container_not_unique"
    ):
        smoke.discover_worker_pool_token_file(fake_run)

    assert calls[0][:2] == ["docker", "ps"]
    assert calls[1][:2] == ["docker", "inspect"]


def test_discover_token_file_requires_service_container() -> None:
    def fake_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return _completed(args, "")

    with pytest.raises(
        smoke.RuntimeSmokeError, match="worker_pool_service_container_missing"
    ):
        smoke.discover_worker_pool_token_file(fake_run)


def test_discover_token_file_requires_unique_bind_mount() -> None:
    bad = _container(
        mounts=[
            {
                "Type": "bind",
                "Source": "C:/secure/a",
                "Destination": smoke.TOKEN_DESTINATION,
            },
            {
                "Type": "bind",
                "Source": "C:/secure/b",
                "Destination": smoke.TOKEN_DESTINATION,
            },
        ]
    )

    def fake_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["docker", "ps"]:
            return _completed(args, "one\n")
        return _completed(args, json.dumps([bad]))

    with pytest.raises(
        smoke.RuntimeSmokeError, match="worker_pool_token_mount_not_unique"
    ):
        smoke.discover_worker_pool_token_file(fake_run)


def test_discover_token_file_accepts_exact_endpoint_and_mount() -> None:
    def fake_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["docker", "ps"]:
            return _completed(args, "one\n")
        return _completed(args, json.dumps([_container()]))

    path = smoke.discover_worker_pool_token_file(fake_run)

    assert str(path).replace("\\", "/").endswith("C:/secure/worker-pool-token")


def test_runtime_identity_is_fail_closed() -> None:
    smoke.validate_runtime_identity(
        {"COMPUTERNAME": smoke.EXPECTED_HOST, "RUNNER_NAME": smoke.EXPECTED_RUNNER}
    )

    with pytest.raises(smoke.RuntimeSmokeError, match="unexpected_runtime_host"):
        smoke.validate_runtime_identity(
            {"COMPUTERNAME": "NOTERI", "RUNNER_NAME": smoke.EXPECTED_RUNNER}
        )

    with pytest.raises(smoke.RuntimeSmokeError, match="unexpected_runtime_runner"):
        smoke.validate_runtime_identity(
            {"COMPUTERNAME": smoke.EXPECTED_HOST, "RUNNER_NAME": "other"}
        )


def test_relative_output_is_resolved_against_execution_cwd(tmp_path: Path) -> None:
    resolved = smoke.resolve_output_path(
        Path("artifacts/engineering-worker-pool-smoke/evidence.json"),
        base=tmp_path,
    )
    assert resolved.is_absolute()
    assert resolved == (
        tmp_path / "artifacts" / "engineering-worker-pool-smoke" / "evidence.json"
    ).resolve()


def test_worker_pool_evidence_requires_replay_and_independent_readback() -> None:
    payload = {
        "result": "WORKER_POOL_SMOKE_PASSED",
        "expected_sha": WORKER_SHA,
        "lane_enabled": False,
        "task_state": "queued",
        "leased_by": None,
        "replay_created": False,
        "independent_readback": True,
        "secrets_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
    }
    smoke.validate_worker_pool_evidence(payload, WORKER_SHA)

    payload["independent_readback"] = False
    with pytest.raises(
        smoke.RuntimeSmokeError,
        match="worker_pool_smoke_evidence_mismatch_independent_readback",
    ):
        smoke.validate_worker_pool_evidence(payload, WORKER_SHA)


def test_runtime_smoke_wraps_external_harness_without_exposing_token_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker_root = tmp_path / "engineering-worker-pool"
    script = worker_root / "scripts" / "worker_pool_smoke.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test harness\n", encoding="utf-8")

    token_file = tmp_path / "private-token"
    token_file.write_text("never-log-this", encoding="utf-8")
    output = tmp_path / "artifacts" / "evidence.json"

    def fake_git_sha(root: Path) -> str:
        return RUNTIME_SHA if root == smoke.ROOT else WORKER_SHA

    monkeypatch.setattr(smoke, "git_sha", fake_git_sha)
    runtime = smoke.WorkerPoolRuntime(
        container_id="container-one",
        token_file=token_file,
        container=_container(),
    )
    monkeypatch.setattr(
        smoke, "discover_worker_pool_runtime", lambda _runner: runtime
    )

    observed_child_output: list[Path] = []

    def fake_subprocess_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        evidence_path = Path(command[command.index("--output") + 1])
        cwd = Path(str(kwargs["cwd"]))
        effective_path = evidence_path if evidence_path.is_absolute() else cwd / evidence_path
        observed_child_output.append(effective_path)
        effective_path.parent.mkdir(parents=True, exist_ok=True)
        effective_path.write_text(
            json.dumps(
                {
                    "result": "WORKER_POOL_SMOKE_PASSED",
                    "expected_sha": WORKER_SHA,
                    "lane_enabled": False,
                    "task_state": "queued",
                    "leased_by": None,
                    "replay_created": False,
                    "independent_readback": True,
                    "secrets_exposed": False,
                    "production_touched": False,
                    "deploy_executed": False,
                    "task_id": "task-1",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", fake_subprocess_run)

    result = smoke.run_runtime_smoke(
        expected_runtime_sha=RUNTIME_SHA,
        expected_worker_pool_sha=WORKER_SHA,
        worker_pool_root=worker_root,
        correlation_id="test-correlation",
        output=output,
        env={"COMPUTERNAME": smoke.EXPECTED_HOST, "RUNNER_NAME": smoke.EXPECTED_RUNNER},
        repair_auth_bind=False,
    )

    assert result["result"] == "WORKER_POOL_RUNTIME_SMOKE_PASSED"
    assert observed_child_output == [output.with_name("worker-pool-evidence.json")]
    assert observed_child_output[0].is_absolute()
    assert result["worker_pool_result"] == "WORKER_POOL_SMOKE_PASSED"
    assert result["independent_readback"] is True
    assert result["replay_created"] is False
    assert result["token_path_exposed"] is False
    assert "private-token" not in output.read_text(encoding="utf-8")
    assert "never-log-this" not in output.read_text(encoding="utf-8")


def test_physical_workflow_requires_session_launcher_and_command_gateway() -> None:
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "engineering-worker-pool-smoke-dev.yml"
    ).read_text(encoding="utf-8")

    assert "session_launcher.py" in workflow
    assert "command_gateway.py" in workflow
    assert "SESSION_LAUNCH_OK" in workflow
    assert "state_validated" in workflow
    assert '"--session-id"' in workflow
    assert '"--risk", "2"' in workflow
    assert "ae9b681b6cbe5c6e0c6c82b187b3245c0749118f" in workflow
    assert "python scripts/engineering_worker_pool_smoke_dev.py" not in workflow



def test_repair_auth_bind_recreates_same_compose_service_without_build_or_pull(
    tmp_path: Path,
) -> None:
    working_dir = tmp_path / "compose"
    working_dir.mkdir()
    compose_file = working_dir / "docker-compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    token_file = tmp_path / "token"
    token_file.write_text("test-token-value", encoding="utf-8")

    current = _container(container_id="old-container")
    current["Config"]["Labels"].update(
        {
            "com.docker.compose.project": "reqsys",
            "com.docker.compose.project.working_dir": str(working_dir),
            "com.docker.compose.project.config_files": str(compose_file),
        }
    )
    current["Config"]["Env"] = [
        "CODEX_WORKER_POOL_EXPECTED_RULES_SHA=" + ("c" * 40)
    ]
    runtime = smoke.WorkerPoolRuntime(
        container_id="old-container",
        token_file=token_file,
        container=current,
    )

    refreshed_container = _container(container_id="new-container")
    calls: list[tuple[list[str], Path, dict[str, str]]] = []

    def fake_compose_run(
        args: list[str], cwd: Path, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append((args, cwd, env))
        return _completed(args, "")

    def fake_docker_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["docker", "ps"]:
            return _completed(args, "new-container\n")
        return _completed(args, json.dumps([refreshed_container]))

    repaired = smoke.repair_worker_pool_auth_bind(
        runtime,
        compose_run=fake_compose_run,
        docker_run=fake_docker_run,
    )

    assert repaired.container_id == "new-container"
    assert len(calls) == 1
    args, cwd, child_env = calls[0]
    assert cwd == working_dir
    assert args[:5] == [
        "docker",
        "compose",
        "--project-name",
        "reqsys",
        "-f",
    ]
    assert "--force-recreate" in args
    assert "--no-deps" in args
    assert "--no-build" in args
    assert args[args.index("--pull") + 1] == "never"
    assert "--wait" in args
    assert args[-1] == smoke.POOL_SERVICE
    assert child_env["CODEX_WORKER_POOL_API_TOKEN_FILE_HOST"] == str(token_file)
    assert child_env["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] == "c" * 40


def test_repair_auth_bind_fails_closed_without_compose_metadata(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("test-token-value", encoding="utf-8")
    runtime = smoke.WorkerPoolRuntime(
        container_id="container-one",
        token_file=token_file,
        container=_container(),
    )

    with pytest.raises(
        smoke.RuntimeSmokeError, match="worker_pool_compose_metadata_missing"
    ):
        smoke.repair_worker_pool_auth_bind(runtime)


def test_runtime_smoke_repairs_auth_bind_once_only_on_401(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worker_root = tmp_path / "engineering-worker-pool"
    script = worker_root / "scripts" / "worker_pool_smoke.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test harness\n", encoding="utf-8")
    token_file = tmp_path / "private-token"
    token_file.write_text("test-token-value", encoding="utf-8")

    old_runtime = smoke.WorkerPoolRuntime(
        container_id="old-container",
        token_file=token_file,
        container=_container(container_id="old-container"),
    )
    new_runtime = smoke.WorkerPoolRuntime(
        container_id="new-container",
        token_file=token_file,
        container=_container(container_id="new-container"),
    )

    monkeypatch.setattr(
        smoke,
        "git_sha",
        lambda root: RUNTIME_SHA if root == smoke.ROOT else WORKER_SHA,
    )
    monkeypatch.setattr(
        smoke, "discover_worker_pool_runtime", lambda _runner: old_runtime
    )

    repairs: list[str] = []

    def fake_repair(
        runtime: smoke.WorkerPoolRuntime,
        *,
        compose_run: smoke.ComposeRun,
        docker_run: smoke.DockerRun,
    ) -> smoke.WorkerPoolRuntime:
        repairs.append(runtime.container_id)
        return new_runtime

    monkeypatch.setattr(smoke, "repair_worker_pool_auth_bind", fake_repair)

    attempts = iter(
        [
            (
                2,
                {
                    "result": "WORKER_POOL_SMOKE_BLOCKED",
                    "reason": "worker_pool_http_401",
                },
            ),
            (
                0,
                {
                    "result": "WORKER_POOL_SMOKE_PASSED",
                    "expected_sha": WORKER_SHA,
                    "lane_enabled": False,
                    "task_state": "queued",
                    "leased_by": None,
                    "replay_created": False,
                    "independent_readback": True,
                    "secrets_exposed": False,
                    "production_touched": False,
                    "deploy_executed": False,
                    "task_id": "task-1",
                },
            ),
        ]
    )
    monkeypatch.setattr(
        smoke, "_run_worker_pool_harness", lambda **_kwargs: next(attempts)
    )

    result = smoke.run_runtime_smoke(
        expected_runtime_sha=RUNTIME_SHA,
        expected_worker_pool_sha=WORKER_SHA,
        worker_pool_root=worker_root,
        correlation_id="repair-correlation",
        output=tmp_path / "evidence.json",
        env={"COMPUTERNAME": smoke.EXPECTED_HOST, "RUNNER_NAME": smoke.EXPECTED_RUNNER},
        repair_auth_bind=True,
    )

    assert repairs == ["old-container"]
    assert result["auth_bind_repaired"] is True
    assert result["worker_pool_result"] == "WORKER_POOL_SMOKE_PASSED"


def test_runtime_smoke_does_not_repair_non_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worker_root = tmp_path / "engineering-worker-pool"
    script = worker_root / "scripts" / "worker_pool_smoke.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test harness\n", encoding="utf-8")
    token_file = tmp_path / "private-token"
    token_file.write_text("test-token-value", encoding="utf-8")
    runtime = smoke.WorkerPoolRuntime(
        container_id="container-one",
        token_file=token_file,
        container=_container(),
    )

    monkeypatch.setattr(
        smoke,
        "git_sha",
        lambda root: RUNTIME_SHA if root == smoke.ROOT else WORKER_SHA,
    )
    monkeypatch.setattr(
        smoke, "discover_worker_pool_runtime", lambda _runner: runtime
    )
    monkeypatch.setattr(
        smoke,
        "_run_worker_pool_harness",
        lambda **_kwargs: (
            2,
            {
                "result": "WORKER_POOL_SMOKE_BLOCKED",
                "reason": "worker_pool_unreachable",
            },
        ),
    )
    monkeypatch.setattr(
        smoke,
        "repair_worker_pool_auth_bind",
        lambda *_args, **_kwargs: pytest.fail("repair must not run"),
    )

    with pytest.raises(smoke.RuntimeSmokeError, match="worker_pool_unreachable"):
        smoke.run_runtime_smoke(
            expected_runtime_sha=RUNTIME_SHA,
            expected_worker_pool_sha=WORKER_SHA,
            worker_pool_root=worker_root,
            correlation_id="negative-control",
            output=tmp_path / "evidence.json",
            env={
                "COMPUTERNAME": smoke.EXPECTED_HOST,
                "RUNNER_NAME": smoke.EXPECTED_RUNNER,
            },
            repair_auth_bind=True,
        )
