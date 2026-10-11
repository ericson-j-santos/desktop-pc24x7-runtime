"""Negative controls for a broker self-refresh that cannot start the handoff.

Only temporary paths and synthetic metadata are used. No host access or recovery.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "desktop_admin_broker.py"
SPEC = importlib.util.spec_from_file_location("broker_refresh_rollback", MODULE)
assert SPEC is not None and SPEC.loader is not None
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    previous_sha, target_sha = "a" * 40, "b" * 40
    python = tmp_path / "python.exe"
    python.write_bytes(b"synthetic")
    launcher = tmp_path / "run.py"
    launcher.write_text("# synthetic\n", encoding="utf-8")
    previous_release = tmp_path / "releases" / previous_sha
    (previous_release / "scripts").mkdir(parents=True)
    (previous_release / "scripts" / "desktop_admin_broker.py").write_text(
        "# previous release\n", encoding="utf-8"
    )
    metadata_path = tmp_path / "metadata.json"
    previous = {
        "source_sha": previous_sha,
        "runtime_root": str(tmp_path),
        "python_executable": str(python),
        "release_root": str(previous_release),
        "poll_seconds": 90,
        "activation_pending": True,
        "requires_uac_activation": True,
        "admin_channel_ready": False,
    }
    metadata_path.write_text(json.dumps(previous), encoding="utf-8")
    activation = tmp_path / "Activate-Desktop-Admin-Broker.cmd"
    activation.write_text("previous\n", encoding="utf-8")

    def fake_git(git, args, **kwargs):
        if args[0] == "clone":
            Path(args[-1]).mkdir(parents=True)
            return ""
        if "rev-parse" in args:
            return target_sha
        if "status" in args:
            return ""
        raise AssertionError("unexpected git operation")

    def fake_copy_release(source, target):
        scripts = target / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        (scripts / "desktop_admin_broker.py").write_text(
            "# candidate release\n", encoding="utf-8"
        )

    written_launchers = []
    def fake_activation(root, *, release_root, python_executable, metadata_path):
        assert root == tmp_path
        assert python_executable == python
        assert metadata_path == tmp_path / "metadata.json"
        written_launchers.append(release_root)
        activation.write_text(str(release_root), encoding="utf-8")
        return activation

    monkeypatch.setattr(broker, "require_windows_desktop", lambda: broker.EXPECTED_HOST)
    monkeypatch.setattr(broker, "_git_executable", lambda: tmp_path / "git.exe")
    monkeypatch.setattr(broker, "_remote_main_sha", lambda git: target_sha)
    monkeypatch.setattr(broker, "_run_git", fake_git)
    monkeypatch.setattr(broker, "_copy_release", fake_copy_release)
    monkeypatch.setattr(broker, "_write_uac_activation_launcher", fake_activation)
    monkeypatch.setattr(
        broker, "load_installed_metadata",
        lambda path: {"metadata": json.loads(metadata_path.read_text(encoding="utf-8"))},
    )
    monkeypatch.setattr(
        broker, "_reconcile_activation_metadata_file",
        lambda path, **kwargs: json.loads(metadata_path.read_text(encoding="utf-8")),
    )
    monkeypatch.setattr(broker, "_acquire_metadata_lock", lambda path: "test-lock")
    monkeypatch.setattr(broker, "_release_broker_lock", lambda lock: None)
    return metadata_path, previous, target_sha, activation, written_launchers


def test_failed_spawn_restores_previous_release(monkeypatch, prepared):
    metadata_path, previous, target_sha, activation, launchers = prepared

    def fail(**kwargs):
        raise broker.BrokerError("user_broker_start_failed")

    monkeypatch.setattr(broker, "start_user_broker", fail)
    with pytest.raises(broker.BrokerError, match="user_broker_start_failed"):
        broker._self_refresh(previous)

    actual = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert actual == previous
    assert activation.read_text(encoding="utf-8") == previous["release_root"]
    assert [p.name for p in launchers] == [target_sha, previous["source_sha"]]
    assert (metadata_path.parent / "releases" / target_sha / "scripts" /
            "desktop_admin_broker.py").is_file()  # Keep forensic release.


def test_false_startup_success_is_rejected_and_rolled_back(monkeypatch, prepared):
    metadata_path, previous, _, activation, _ = prepared
    monkeypatch.setattr(
        broker, "start_user_broker",
        lambda **kwargs: {"startup_survived": False},
    )
    with pytest.raises(broker.BrokerError, match="user_broker_start_not_confirmed"):
        broker._self_refresh(previous)
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == previous
    assert activation.read_text(encoding="utf-8") == previous["release_root"]


def test_concurrent_metadata_change_blocks_rollback(monkeypatch, prepared):
    metadata_path, previous, target_sha, activation, launchers = prepared

    def collide(**kwargs):
        state = json.loads(metadata_path.read_text(encoding="utf-8"))
        state["updated_by_other_writer"] = True
        metadata_path.write_text(json.dumps(state), encoding="utf-8")
        raise broker.BrokerError("user_broker_start_failed")

    monkeypatch.setattr(broker, "start_user_broker", collide)
    with pytest.raises(broker.BrokerError, match="self_refresh_rollback_conflict"):
        broker._self_refresh(previous)
    actual = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert actual["source_sha"] == target_sha
    assert actual["updated_by_other_writer"] is True
    assert activation.read_text(encoding="utf-8").endswith(target_sha)
    assert len(launchers) == 1


def test_missing_previous_release_fails_closed(monkeypatch, prepared):
    metadata_path, previous, target_sha, activation, launchers = prepared
    old_script = (metadata_path.parent / "releases" / previous["source_sha"] /
                  "scripts" / "desktop_admin_broker.py")
    old_script.unlink()
    monkeypatch.setattr(
        broker, "start_user_broker",
        lambda **kwargs: (_ for _ in ()).throw(
            broker.BrokerError("user_broker_start_failed")
        ),
    )
    with pytest.raises(broker.BrokerError, match="self_refresh_previous_release_unavailable"):
        broker._self_refresh(previous)
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["source_sha"] == target_sha
    assert activation.read_text(encoding="utf-8").endswith(target_sha)
    assert len(launchers) == 1
