from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import orchestrator_dev_runner_preflight as probe

SHA = "a" * 40
CORRELATION = "orchestrator-preflight-test"


def desktop_worker():
    return {
        "device_name": "DESKTOP-PDQK954",
        "fresh": True,
        "controller_online": True,
        "auth_valid": True,
        "profile": "NORMAL",
    }


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("GH_TOKEN", "synthetic-token-must-not-be-reported")
    monkeypatch.setattr(probe, "require_source", lambda expected: None)
    monkeypatch.setattr(
        probe.bootstrap, "validate_host", lambda: "DESKTOP-PDQK954",
    )

    def api(path, *, method="GET", token):
        calls.append((method, path))
        assert method == "GET"
        assert path == (
            "/repos/ericson-j-santos/reqsys-engineering-orchestrator/"
            "actions/runners?per_page=100"
        )
        return {"total_count": 0, "runners": []}

    monkeypatch.setattr(probe.bootstrap, "api_json", api)
    monkeypatch.setattr(
        probe, "read_loopback",
        lambda path: {"ready": True} if path == "/readyz"
        else {"workers": [desktop_worker()]},
    )

    def forbidden(*args, **kwargs):
        pytest.fail("preflight attempted mutation")

    for name in (
        "registration_token", "ensure_runner_binaries", "register_runner",
        "run_config", "persist",
    ):
        monkeypatch.setattr(probe.bootstrap, name, forbidden)
    monkeypatch.setattr(probe.bootstrap.watchdog, "start_runner", forbidden)
    return tmp_path, calls


def test_preflight_is_read_only_and_replay_has_no_effect(prepared):
    root, calls = prepared
    before = list(root.rglob("*"))
    first = probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    second = probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert first == second
    assert first["state"] == "READ_ONLY_PLAN_RECORDED_EXECUTION_PENDING"
    assert first["registration_required"] is True
    for field in (
        "execution_authorized", "physical_pickup_proven",
        "continuous_operation_proven", "registration_token_requested",
        "runner_version_preflight_proven",
    ):
        assert first[field] is False
    assert list(root.rglob("*")) == before
    assert len(calls) == 2
    assert "synthetic-token" not in json.dumps(first)


def test_profile_cannot_be_changed():
    with pytest.raises(TypeError):
        probe.PROFILE["repository"] = "other/repository"


def test_cli_has_no_apply_or_target_override(prepared):
    for extra in (["--apply"], ["--repository", "other/repo"]):
        with pytest.raises(SystemExit) as error:
            probe.main([
                "--expected-sha", SHA, "--correlation-id", CORRELATION, *extra,
            ])
        assert error.value.code == 2


@pytest.mark.parametrize("host", ["Noteri", "DESKTOP-RP23OGS", "another-host"])
def test_wrong_host_rejected_before_registry(prepared, monkeypatch, host):
    _, calls = prepared
    monkeypatch.setattr(probe.bootstrap, "validate_host", lambda: host)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "orchestrator_runner_host_not_authorized"
    assert calls == []


@pytest.mark.parametrize("field", ["fresh", "controller_online", "auth_valid"])
def test_unready_worker_is_blocked(prepared, monkeypatch, field):
    worker = desktop_worker()
    worker[field] = False
    monkeypatch.setattr(
        probe, "read_loopback",
        lambda path: {"ready": True} if path == "/readyz"
        else {"workers": [worker]},
    )
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "orchestrator_desktop_worker_not_ready"


def test_duplicate_worker_and_false_readiness_are_blocked(prepared, monkeypatch):
    for ready, workers, expected in [
        (False, [desktop_worker()], "orchestrator_not_ready"),
        (True, [desktop_worker(), desktop_worker()],
         "orchestrator_desktop_worker_not_unique"),
    ]:
        monkeypatch.setattr(
            probe, "read_loopback",
            lambda path: {"ready": ready} if path == "/readyz"
            else {"workers": workers},
        )
        with pytest.raises(probe.bootstrap.BootstrapError) as error:
            probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
        assert error.value.state == expected


def test_incomplete_registry_is_blocked(prepared, monkeypatch):
    monkeypatch.setattr(
        probe.bootstrap, "api_json",
        lambda *a, **k: {"total_count": 101, "runners": []},
    )
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_registry_incomplete"


def test_existing_directory_is_preserved(prepared):
    root, _ = prepared
    home = root / "EngineeringOrchestratorDEV" / "GitHubRunner"
    home.mkdir(parents=True)
    sentinel = home / "unrelated.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_home_not_empty"
    assert sentinel.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("link_mode,attributes", [
    (stat.S_IFDIR | 0o700, 0x400),
    (stat.S_IFLNK | 0o700, 0),
])
def test_ancestor_above_localappdata_is_checked(
    prepared, monkeypatch, link_mode, attributes,
):
    root, calls = prepared
    ancestor = root / "redirected"
    local = ancestor / "Local"
    local.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    real_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        if path == ancestor:
            return SimpleNamespace(st_mode=link_mode, st_file_attributes=attributes)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_path_link_rejected"
    assert calls == []


def test_file_ancestor_is_rejected(prepared, monkeypatch):
    root, calls = prepared
    ancestor = root / "not-a-directory"
    ancestor.write_text("preserve", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(ancestor / "Local"))
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_path_type_invalid"
    assert calls == []


def test_path_errors_are_sanitized(prepared, monkeypatch):
    root, _ = prepared
    real_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        if path == root:
            raise PermissionError("sensitive-filesystem-detail")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_path_unavailable"
    assert "sensitive" not in str(error.value)


def registered_metadata(root, *, local_id=42, remote_id=42):
    home = root / "EngineeringOrchestratorDEV" / "GitHubRunner"
    home.mkdir(parents=True)
    metadata = {
        "gitHubUrl": "https://github.com/" + probe.PROFILE["repository"],
        "agentName": probe.PROFILE["runner_name"],
        "runnerName": probe.PROFILE["runner_name"],
        "agentId": local_id,
    }
    (home / ".runner").write_text(json.dumps(metadata), encoding="utf-8-sig")
    remote = {
        "id": remote_id,
        "name": probe.PROFILE["runner_name"],
        "status": "online",
        "busy": False,
        "labels": [{"name": label} for label in probe.REQUIRED_LABELS],
    }
    return home, metadata, remote


def test_metadata_binding_accepts_bom_but_never_reads_credentials(
    prepared, monkeypatch,
):
    root, _ = prepared
    home, metadata, remote = registered_metadata(root)
    (home / ".credentials").write_text("synthetic-do-not-open", encoding="utf-8")
    monkeypatch.setattr(
        probe.bootstrap, "api_json",
        lambda *a, **k: {"total_count": 1, "runners": [remote]},
    )
    real_open = Path.open

    def checked_open(path, *args, **kwargs):
        assert path.name != ".credentials"
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked_open)
    result = probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert result["registration_required"] is False
    assert result["observed_runner_id"] == 42
    assert result["physical_pickup_proven"] is False
    metadata["gitHubUrl"] = "https://github.com/other/repository"
    (home / ".runner").write_text(json.dumps(metadata), encoding="utf-8-sig")
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_repository_mismatch"


@pytest.mark.parametrize("local_id,remote_id", [
    (True, 1), (1, True), (0, 0), (-1, -1), ("42", 42), (42, "42"),
])
def test_metadata_ids_must_be_positive_integers(
    prepared, monkeypatch, local_id, remote_id,
):
    root, _ = prepared
    _, _, remote = registered_metadata(root, local_id=local_id, remote_id=remote_id)
    monkeypatch.setattr(
        probe.bootstrap, "api_json",
        lambda *a, **k: {"total_count": 1, "runners": [remote]},
    )
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_id_mismatch"


def test_conflicting_name_alias_is_rejected(prepared, monkeypatch):
    root, _ = prepared
    home, metadata, remote = registered_metadata(root)
    metadata["runnerName"] = "foreign-runner"
    (home / ".runner").write_text(json.dumps(metadata), encoding="utf-8-sig")
    monkeypatch.setattr(
        probe.bootstrap, "api_json",
        lambda *a, **k: {"total_count": 1, "runners": [remote]},
    )
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.preflight(expected_sha=SHA, correlation_id=CORRELATION)
    assert error.value.state == "runner_name_mismatch"


@pytest.mark.parametrize("observed,dirty,origin,expected", [
    ("b" * 40, "", "https://github.com/" + probe.SOURCE_REPOSITORY,
     "source_sha_mismatch"),
    (SHA, " M scripts/example.py", "https://github.com/" + probe.SOURCE_REPOSITORY,
     "source_tracked_tree_dirty"),
    (SHA, "", "https://github.com/other/repository", "source_repository_mismatch"),
])
def test_source_readback_rejects_invalid_state(
    monkeypatch, observed, dirty, origin, expected,
):
    values = iter([observed, dirty, origin, "\n".join(probe.SOURCE_PATHS)])
    monkeypatch.setattr(
        probe.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=next(values)),
    )
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.require_source(SHA)
    assert error.value.state == expected


def test_source_readback_accepts_exact_clean_tracked_source(monkeypatch):
    values = iter([
        SHA, "", "https://github.com/" + probe.SOURCE_REPOSITORY,
        "\n".join(probe.SOURCE_PATHS),
    ])
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
        assert "GH_TOKEN" not in kwargs["env"]
        assert "GITHUB_TOKEN" not in kwargs["env"]
        return SimpleNamespace(returncode=0, stdout=next(values))

    monkeypatch.setenv("GH_TOKEN", "synthetic-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-secret")
    monkeypatch.setattr(probe.subprocess, "run", run)
    probe.require_source(SHA)
    assert "ls-files" in commands[-1]
    assert "--error-unmatch" in commands[-1]
    assert set(probe.SOURCE_PATHS).issubset(commands[-1])


@pytest.mark.parametrize("exit_code,tracked", [
    (1, ""), (0, "\n".join(probe.SOURCE_PATHS[1:])),
])
def test_untracked_probe_cannot_borrow_trusted_head(monkeypatch, exit_code, tracked):
    values = iter([SHA, "", "https://github.com/" + probe.SOURCE_REPOSITORY])

    def run(command, **kwargs):
        if "ls-files" in command:
            return SimpleNamespace(returncode=exit_code, stdout=tracked)
        return SimpleNamespace(returncode=0, stdout=next(values))

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.require_source(SHA)
    assert error.value.state == "source_files_untracked"


def test_imported_module_from_other_checkout_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(
        probe.bootstrap, "__file__", str(tmp_path / "bootstrap_dedicated_runtime_runner.py"),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("foreign import must be rejected before Git")

    monkeypatch.setattr(probe.subprocess, "run", forbidden)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.require_source(SHA)
    assert error.value.state == "source_import_path_mismatch"


@pytest.mark.parametrize("status,body,expected", [
    (302, b'{"ready": true}', "orchestrator_http_not_ready"),
    (200, b"x" * (probe.MAX_RESPONSE_BYTES + 1), "orchestrator_response_too_large"),
    (200, b"not-json", "orchestrator_readback_unavailable"),
    (200, b"[]", "orchestrator_response_invalid"),
], ids=["redirect", "oversize", "invalid-json", "invalid-type"])
def test_loopback_reader_is_bounded_and_rejects_invalid_responses(
    monkeypatch, status, body, expected,
):
    seen = []

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 8787, 5)

        def request(self, method, path, headers):
            seen.append((method, path))
            assert method == "GET"

        def getresponse(self):
            def read(limit):
                assert limit == probe.MAX_RESPONSE_BYTES + 1
                return body
            return SimpleNamespace(status=status, read=read)

        def close(self):
            seen.append(("closed", ""))

    monkeypatch.setattr(probe, "HTTPConnection", Connection)
    with pytest.raises(probe.bootstrap.BootstrapError) as error:
        probe.read_loopback("/readyz")
    assert error.value.state == expected
    assert seen == [("GET", "/readyz"), ("closed", "")]


def test_persistent_listener_does_not_inherit_github_tokens(monkeypatch, tmp_path):
    watchdog = probe.bootstrap.watchdog
    monkeypatch.setenv("GH_TOKEN", "synthetic-admin-token")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-job-token")
    monkeypatch.setenv("RUNNER_TRACKING_ID", "synthetic-job")
    monkeypatch.setattr(watchdog, "validate_runner_home", lambda path: path)
    monkeypatch.setattr(watchdog, "inspect_runner_version", lambda path: {})
    snapshots = iter([
        {"matching_pids": [], "unresolved_pids": []},
        {"matching_pids": [123], "unresolved_pids": []},
    ])
    monkeypatch.setattr(
        watchdog, "runner_process_snapshot", lambda path: next(snapshots),
    )
    monkeypatch.setattr(watchdog, "_creationflags", lambda: 0)
    captured = {}

    def popen(*args, **kwargs):
        captured.update(kwargs["env"])
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(watchdog.subprocess, "Popen", popen)
    watchdog.start_runner(tmp_path / "runner", tmp_path / "runner.log")
    assert "GH_TOKEN" not in captured
    assert "GITHUB_TOKEN" not in captured
    assert "RUNNER_TRACKING_ID" not in captured
