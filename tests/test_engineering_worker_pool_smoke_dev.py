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


def _container(*, running: bool = True, mounts: list[dict] | None = None) -> dict:
    return {
        "Config": {"Labels": {"com.docker.compose.service": smoke.POOL_SERVICE}},
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
    monkeypatch.setattr(
        smoke, "discover_worker_pool_token_file", lambda _runner: token_file
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
    assert "ac2297988651f41ab03469808e41f83496e9c58f" in workflow
    assert "python scripts/engineering_worker_pool_smoke_dev.py" not in workflow
    assert "cancel-in-progress: true" in workflow
    assert "name: Ensure dedicated Desktop runner labels" in workflow
    assert workflow.count("runs-on: [self-hosted, Windows, X64]") == 1
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev]" in workflow
    assert 'if ($env:COMPUTERNAME -ne "DESKTOP-PDQK954")' in workflow
    assert "DESKTOP_BOOTSTRAP_HOST_MISMATCH" in workflow
    assert "--non-interactive-auth" in workflow
    assert "needs: prepare_runner" in workflow
    assert workflow.count("session_launcher.py") >= 2
    assert workflow.count("command_gateway.py") >= 2
    assert workflow.count("- scripts/activate_desktop_runtime_runner.py") == 2
    assert "Repair runner label contract through Command Gateway" in workflow
    assert "python scripts/activate_desktop_runtime_runner.py" not in workflow


def test_physical_workflow_owns_queue_watchdog_without_coupling_unit_ci() -> None:
    root = Path(__file__).resolve().parents[1]
    physical = (
        root
        / ".github"
        / "workflows"
        / "engineering-worker-pool-smoke-dev.yml"
    ).read_text(encoding="utf-8")
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "name: Physical runner queue watchdog" in physical
    assert 'STALL_AFTER_SECONDS: "60"' in physical
    assert "timeout-minutes: 2" in physical
    assert "scripts/progress_watchdog.py" in physical
    assert "actions: write" in physical
    assert "TARGET_RUN_ID: ${{ github.run_id }}" in physical
    assert "getWorkflowRun" in physical
    assert "listJobsForWorkflowRun" in physical
    assert "runner_id" in physical
    assert "cancelWorkflowRun" in physical
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in physical
    assert "alternative_route_available: false" in physical
    assert "name: Physical runner queue watchdog" not in ci
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" not in ci



def test_runtime_smoke_reconciles_stale_bind_on_401_then_retries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker_root = tmp_path / "engineering-worker-pool"
    harness = worker_root / "scripts" / "worker_pool_smoke.py"
    harness.parent.mkdir(parents=True)
    harness.write_text("# harness\n", encoding="utf-8")

    token_file = tmp_path / "private-token"
    token_file.write_text("x" * 48, encoding="utf-8")
    output = tmp_path / "artifacts" / "evidence.json"

    monkeypatch.setattr(
        smoke,
        "git_sha",
        lambda root: RUNTIME_SHA if root == smoke.ROOT else WORKER_SHA,
    )
    monkeypatch.setattr(
        smoke, "discover_worker_pool_token_file", lambda _runner: token_file
    )

    calls: list[str] = []
    harness_attempts = 0

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal harness_attempts
        script_name = Path(command[1]).name
        calls.append(script_name)
        evidence_path = Path(command[command.index("--output") + 1])
        evidence_path.parent.mkdir(parents=True, exist_ok=True)

        if script_name == "engineering_worker_pool_auth_reconcile_dev.py":
            evidence_path.write_text(
                json.dumps(
                    {
                        "result": "WORKER_POOL_AUTH_RECONCILE_PASSED",
                        "existing_token_reused": True,
                        "token_rotated": False,
                        "service_recreated": True,
                        "bind_mount_resynced": True,
                        "authenticated_readback": True,
                        "secret_value_exposed": False,
                        "production_touched": False,
                        "deploy_executed": False,
                        "reboot_executed": False,
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        harness_attempts += 1
        if harness_attempts == 1:
            evidence_path.write_text(
                json.dumps(
                    {
                        "result": "WORKER_POOL_SMOKE_BLOCKED",
                        "reason": "worker_pool_http_401",
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="")

        evidence_path.write_text(
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
                    "task_id": "task-after-reconcile",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)

    result = smoke.run_runtime_smoke(
        expected_runtime_sha=RUNTIME_SHA,
        expected_worker_pool_sha=WORKER_SHA,
        worker_pool_root=worker_root,
        correlation_id="reconcile-correlation",
        output=output,
        env={"COMPUTERNAME": smoke.EXPECTED_HOST, "RUNNER_NAME": smoke.EXPECTED_RUNNER},
    )

    assert calls == [
        "worker_pool_smoke.py",
        "engineering_worker_pool_auth_reconcile_dev.py",
        "worker_pool_smoke.py",
    ]
    assert result["auth_reconciled"] is True
    assert result["service_recreated"] is True
    assert result["smoke_attempts"] == 2
    assert result["independent_readback"] is True


def test_runtime_smoke_does_not_reconcile_non_auth_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker_root = tmp_path / "engineering-worker-pool"
    harness = worker_root / "scripts" / "worker_pool_smoke.py"
    harness.parent.mkdir(parents=True)
    harness.write_text("# harness\n", encoding="utf-8")
    token_file = tmp_path / "private-token"
    token_file.write_text("x" * 48, encoding="utf-8")

    monkeypatch.setattr(
        smoke,
        "git_sha",
        lambda root: RUNTIME_SHA if root == smoke.ROOT else WORKER_SHA,
    )
    monkeypatch.setattr(
        smoke, "discover_worker_pool_token_file", lambda _runner: token_file
    )

    def fail_once(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if Path(command[1]).name == "engineering_worker_pool_auth_reconcile_dev.py":
            pytest.fail("reconciliation must only run for worker_pool_http_401")
        evidence_path = Path(command[command.index("--output") + 1])
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(
                {
                    "result": "WORKER_POOL_SMOKE_BLOCKED",
                    "reason": "worker_pool_unreachable",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", fail_once)

    with pytest.raises(smoke.RuntimeSmokeError, match="worker_pool_unreachable"):
        smoke.run_runtime_smoke(
            expected_runtime_sha=RUNTIME_SHA,
            expected_worker_pool_sha=WORKER_SHA,
            worker_pool_root=worker_root,
            correlation_id="non-auth-correlation",
            output=tmp_path / "artifacts" / "evidence.json",
            env={
                "COMPUTERNAME": smoke.EXPECTED_HOST,
                "RUNNER_NAME": smoke.EXPECTED_RUNNER,
            },
        )
