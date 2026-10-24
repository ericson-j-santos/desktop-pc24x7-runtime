from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import launch_desktop_runtime_session_conflict_uac as launcher  # noqa: E402
import resolve_desktop_runtime_session_conflict as resolver  # noqa: E402


class FakeWatchdog:
    def __init__(self, paths: dict[int, Path | None]) -> None:
        self.paths = paths

    def _runner_process_ids(self) -> list[int]:
        return list(self.paths)

    def _process_executable_path(self, pid: int) -> Path | None:
        return self.paths[pid]


def prepare_runner_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    local = tmp_path / "LocalAppData"
    target_home = local / "DesktopPC24x7" / "GitHubRunner"
    legacy_home = local / "ReqSys" / "Pc24x7GitHubRunner"
    target_listener = target_home / "bin" / "Runner.Listener.exe"
    legacy_listener = legacy_home / "bin" / "Runner.Listener.exe"
    target_listener.parent.mkdir(parents=True)
    legacy_listener.parent.mkdir(parents=True)
    target_listener.touch()
    legacy_listener.touch()
    (target_home / ".runner").write_text(
        json.dumps({"agentName": resolver.EXPECTED_RUNNER}), encoding="utf-8"
    )
    diag = target_home / "_diag"
    diag.mkdir()
    (diag / "Runner_current.log").write_text(
        "TaskAgentSessionConflictException\n"
        "A session for this runner already exists.\n",
        encoding="utf-8",
    )
    return local, target_listener, legacy_listener


def test_expected_pid_is_bound_to_prevalidated_unresolved_listener(
    tmp_path: Path,
) -> None:
    local, target_listener, legacy_listener = prepare_runner_layout(tmp_path)
    watchdog = FakeWatchdog(
        {101: target_listener, 202: legacy_listener, 303: None}
    )

    assert resolver.validate_and_select_pid(watchdog, local, expected_pid=303) == 303


def test_expected_pid_rejects_reused_legacy_identity(tmp_path: Path) -> None:
    local, target_listener, legacy_listener = prepare_runner_layout(tmp_path)
    watchdog = FakeWatchdog(
        {101: target_listener, 202: legacy_listener, 303: legacy_listener}
    )

    with pytest.raises(
        resolver.ConflictResolutionError,
        match="expected_listener_identity_mismatch",
    ):
        resolver.validate_and_select_pid(watchdog, local, expected_pid=303)


def test_evidence_path_is_confined_to_pid_specific_runtime_directory(
    tmp_path: Path,
) -> None:
    local = tmp_path / "LocalAppData"
    allowed = (
        local / "DesktopPC24x7" / "ConflictResolution" / "result-303.json"
    )

    assert resolver.validated_evidence_path(local, str(allowed), 303) == allowed
    with pytest.raises(
        resolver.ConflictResolutionError, match="evidence_path_not_allowed"
    ):
        resolver.validated_evidence_path(local, str(tmp_path / "result-303.json"), 303)
    with pytest.raises(
        resolver.ConflictResolutionError, match="evidence_filename_not_allowed"
    ):
        resolver.validated_evidence_path(
            local,
            str(allowed.with_name("result-404.json")),
            303,
        )


def test_uac_launcher_arguments_bind_pid_and_evidence(tmp_path: Path) -> None:
    script = tmp_path / "resolve.py"
    evidence = tmp_path / "result-303.json"

    params = launcher.build_resolver_arguments(script, 303, evidence)

    assert params == subprocess.list2cmdline(
        [
            str(script),
            "--confirm",
            resolver.CONFIRM,
            "--expected-pid",
            "303",
            "--evidence-file",
            str(evidence),
        ]
    )
