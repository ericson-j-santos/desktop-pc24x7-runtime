from __future__ import annotations

import importlib.util
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "desktop_admin_broker.py"
SPEC = importlib.util.spec_from_file_location("desktop_admin_broker", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def gh_comment(
    *,
    comment_id: int = 100,
    body: str = "/desktop-runtime admin status",
    actor: str = "ericson-j-santos",
    association: str = "OWNER",
    created: datetime | None = None,
    edited: bool = False,
) -> dict:
    created = created or datetime.now(timezone.utc)
    updated = created + timedelta(seconds=1) if edited else created
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": actor},
        "author_association": association,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "updated_at": updated.isoformat().replace("+00:00", "Z"),
    }


def test_rejects_other_host(monkeypatch) -> None:
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
    with pytest.raises(m.BrokerError, match="host não autorizado"):
        m.require_windows_desktop()


def test_allowlist_is_exact_and_has_no_shell_action() -> None:
    assert set(m.ALLOWED_COMMANDS) == {
        "/desktop-runtime admin status",
        "/desktop-runtime admin recover-rdc",
        "/desktop-runtime admin recover-runner",
        "/desktop-runtime admin recover-control-plane",
        "/desktop-runtime admin activate-watchdog",
    }
    source = MODULE.read_text(encoding="utf-8").casefold()
    assert "shell=true" not in source
    assert "host.shell" not in source
    assert "reboot" not in " ".join(m.ALLOWED_COMMANDS).casefold()


def test_transport_is_outbound_public_github_only_without_secret_or_listener() -> None:
    source = MODULE.read_text(encoding="utf-8")
    lowered = source.casefold()
    assert "api.github.com/repos/{repository}/issues/{issue_number}/comments" in lowered
    assert "authorization" not in lowered
    assert "gh_token" not in lowered
    assert "github_token" not in lowered
    assert "threadinghttpserver" not in lowered
    assert "http.server" not in lowered
    assert ".listen(" not in lowered
    assert ".bind(" not in lowered


def test_comment_authorization_requires_owner_exact_unedited_fresh() -> None:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(seconds=30)
    assert m.authorize_comment(gh_comment(created=now), not_before=not_before, reference_time=now) == "status"
    assert m.authorize_comment(gh_comment(actor="other", created=now), not_before=not_before, reference_time=now) is None
    assert m.authorize_comment(gh_comment(association="MEMBER", created=now), not_before=not_before, reference_time=now) is None
    assert m.authorize_comment(gh_comment(body="/desktop-runtime admin shell", created=now), not_before=not_before, reference_time=now) is None
    assert m.authorize_comment(gh_comment(created=now, edited=True), not_before=not_before, reference_time=now) is None
    assert m.authorize_comment(
        gh_comment(created=now - timedelta(seconds=m.MAX_COMMENT_AGE_SECONDS + 1)),
        not_before=now - timedelta(hours=1),
        reference_time=now,
    ) is None


def test_comment_before_activation_is_rejected() -> None:
    now = datetime.now(timezone.utc)
    comment = gh_comment(created=now - timedelta(seconds=5))
    assert m.authorize_comment(
        comment,
        not_before=now,
        reference_time=now,
    ) is None


def test_process_once_is_idempotent_by_comment_id(monkeypatch, tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    metadata = {
        "runtime_root": str(tmp_path),
        "not_before": (now - timedelta(seconds=30)).isoformat(),
    }
    comment = gh_comment(comment_id=101, created=now)
    monkeypatch.setattr(m, "fetch_comments", lambda since: [comment, comment])
    calls = []
    monkeypatch.setattr(
        m,
        "execute_action",
        lambda action, meta, comment_id: calls.append((action, comment_id)) or {"ok": True},
    )
    first = m.process_once(metadata, reference_time=now)
    second = m.process_once(metadata, reference_time=now)
    assert first["commands_accepted"] == 1
    assert second["commands_accepted"] == 0
    assert calls == [("status", 101)]


def test_failed_command_is_recorded_and_not_replayed(monkeypatch, tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    metadata = {
        "runtime_root": str(tmp_path),
        "not_before": (now - timedelta(seconds=30)).isoformat(),
    }
    comment = gh_comment(comment_id=102, body="/desktop-runtime admin recover-rdc", created=now)
    monkeypatch.setattr(m, "fetch_comments", lambda since: [comment])
    monkeypatch.setattr(m, "execute_action", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("known failure")))
    first = m.process_once(metadata, reference_time=now)
    second = m.process_once(metadata, reference_time=now)
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert first["commands_accepted"] == 1
    assert second["commands_accepted"] == 0
    assert state["accepted"]["status"] == "failed"
    assert state["accepted"]["comment_id"] == 102


def test_install_stages_release_and_marks_uac_pending(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in (
        "desktop_admin_broker.py",
        "desktop_admin_broker_uac_launcher.py",
        m.WATCHDOG_SCRIPT,
        m.WATCHDOG_UAC_SCRIPT,
        m.RDC_RECOVERY_SCRIPT,
        m.RUNNER_BOOTSTRAP_SCRIPT,
        m.READBACK_SCRIPT,
    ):
        (scripts / name).write_text("# stub\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    python = tmp_path / "python.exe"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    stable_python = runtime / m.PERSISTED_PYTHON_DIR / "runtime-hash" / "python.exe"
    stable_python.parent.mkdir(parents=True)
    stable_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        m,
        "stage_persistent_python",
        lambda python_executable, runtime_root: {
            "python_executable": stable_python,
            "runtime_root": stable_python.parent,
            "version": "3.12.10",
            "executable_sha256": "f" * 64,
            "reused": False,
        },
    )
    monkeypatch.setattr(
        m,
        "register_task",
        lambda **kwargs: (_ for _ in ()).throw(m.BrokerError("task_scheduler_access_denied")),
    )
    monkeypatch.setattr(
        m,
        "register_user_autostart",
        lambda **kwargs: {
            "ok": True,
            "mode": "HKCU_RUN_AT_LOGON",
            "readback_verified": True,
            "requires_admin": False,
        },
    )
    monkeypatch.setattr(
        m,
        "start_user_broker",
        lambda **kwargs: {
            "requested": True,
            "pid": 4321,
            "functional_success_proven": False,
        },
    )
    result = m.install(
        source,
        source_sha="a" * 40,
        python_executable=python,
        runtime_root=runtime,
        poll_seconds=90,
        confirm=m.INSTALL_CONFIRM,
    )
    assert result["ok"] is True
    assert result["activation_pending"] is True
    assert result["requires_uac_activation"] is True
    assert result["user_autostart"]["mode"] == "HKCU_RUN_AT_LOGON"
    assert result["user_autostart"]["readback_verified"] is True
    assert result["start"]["requested"] is True
    assert result["functional_success_proven"] is False
    metadata = json.loads((runtime / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["activation_pending"] is True
    assert metadata["fallback_persistence"]["mode"] == "HKCU_RUN_AT_LOGON"
    assert metadata["fallback_persistence"]["readback_verified"] is True
    assert metadata["fallback_start_requested"] is True
    assert (runtime / "releases" / ("a" * 40) / "scripts" / "desktop_admin_broker.py").is_file()
    assert (runtime / "releases" / ("a" * 40) / "scripts" / "desktop_admin_broker_uac_launcher.py").is_file()
    activation = runtime / "Activate-Desktop-Admin-Broker.cmd"
    assert activation.is_file()
    activation_text = activation.read_text(encoding="utf-8")
    assert "LAUNCH-DESKTOP-ADMIN-BROKER-UAC" in activation_text
    assert "--metadata" in activation_text
    assert "--command" not in activation_text
    assert "--action" not in activation_text


def test_recover_runner_uses_fixed_noninteractive_bootstrap(monkeypatch, tmp_path: Path) -> None:
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / m.RUNNER_BOOTSTRAP_SCRIPT).write_text("# stub\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append([str(item) for item in argv])
        payload = {
            "ok": True,
            "state": "runtime_active",
            "runner_running": True,
            "runner_registry_present": True,
            "runner_registry_status": "online",
            "runner_registry_labels_ok": True,
            "runner_registered_now": True,
            "runner_started_now": True,
        }
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload) + "\n", stderr="")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    result = m._recover_runner(
        {
            "release_root": str(release),
            "source_sha": "a" * 40,
        }
    )

    assert result["bootstrap_state"] == "runtime_active"
    assert result["runner_registry_status"] == "online"
    assert len(calls) == 1
    argv = calls[0]
    assert "--non-interactive-auth" in argv
    assert argv[argv.index("--repo-root") + 1] == str(release)
    assert argv[argv.index("--source-sha") + 1] == "a" * 40


def test_recover_runner_fails_closed_on_bootstrap_error(monkeypatch, tmp_path: Path) -> None:
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / m.RUNNER_BOOTSTRAP_SCRIPT).write_text("# stub\n", encoding="utf-8")
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            4,
            stdout='{"ok": false, "state": "github_auth_required"}\n',
            stderr="",
        ),
    )
    with pytest.raises(m.BrokerError, match="runner_bootstrap_failed:github_auth_required"):
        m._recover_runner(
            {
                "release_root": str(release),
                "source_sha": "b" * 40,
            }
        )


def test_register_task_contract_requires_s4u_highest() -> None:
    source = MODULE.read_text(encoding="utf-8")
    assert "TASK_LOGON_S4U = 2" in source
    assert "TASK_RUNLEVEL_HIGHEST = 1" in source
    assert 'definition.Principal' in source
    assert 'principal.LogonType = TASK_LOGON_S4U' in source
    assert 'principal.RunLevel = TASK_RUNLEVEL_HIGHEST' in source


def test_runtime_broker_is_isolated_from_reqsys_control_channel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = MODULE.read_text(encoding="utf-8")
    assert 'REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"' in source
    assert "ISSUE_NUMBER = 2" in source
    assert 'TASK_LEAF = "DesktopPc24x7AdminBroker"' in source
    assert 'RUNNER_BOOTSTRAP_SCRIPT = "activate_desktop_runtime_runner.py"' in source
    assert '"/reqsys admin desktop ' not in source
    assert '"/desktop-runtime admin recover-control-plane"' in source
    assert '"/desktop-runtime admin activate-watchdog"' in source
    assert '"DesktopPC24x7" / "ControlPlaneWatchdog"' in source
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert m.default_runtime_root() == tmp_path / "DesktopPC24x7" / "AdminBroker"


def test_isolated_watchdog_commands_are_authorized() -> None:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(seconds=10)
    expected = {
        "/desktop-runtime admin recover-control-plane": "recover-control-plane",
        "/desktop-runtime admin activate-watchdog": "activate-watchdog",
    }
    for body, action in expected.items():
        assert m.authorize_comment(
            gh_comment(body=body, created=now),
            not_before=not_before,
            reference_time=now,
        ) == action


def test_watchdog_metadata_uses_runtime_owned_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert m.watchdog_runtime_metadata() == (
        tmp_path / "DesktopPC24x7" / "ControlPlaneWatchdog" / "metadata.json"
    )


def test_recover_runner_accepts_local_listener_partial_until_independent_pickup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / m.RUNNER_BOOTSTRAP_SCRIPT).write_text("# stub\n", encoding="utf-8")
    payload = {
        "ok": False,
        "state": "listener_running_pickup_required",
        "local_recovery_ok": True,
        "github_pickup_required": True,
        "github_pickup_proven": False,
        "runner_running": True,
        "runner_registry_present": None,
        "runner_registry_status": "unknown",
        "runner_registry_labels_ok": None,
        "runner_registered_now": False,
        "runner_started_now": True,
    }
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            3,
            stdout=json.dumps(payload) + "\n",
            stderr="",
        ),
    )

    result = m._recover_runner(
        {
            "release_root": str(release),
            "source_sha": "a" * 40,
        }
    )

    assert result["bootstrap_state"] == "listener_running_pickup_required"
    assert result["local_recovery_ok"] is True
    assert result["github_pickup_required"] is True
    assert result["github_pickup_proven"] is False
    assert result["runner_running"] is True


def test_recover_control_plane_recovers_runner_without_uac_or_rdc_dependency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "watchdog"
    runtime.mkdir()
    metadata_path = runtime / "metadata.json"
    metadata_path.write_text(
        json.dumps(
            {
                "runtime_root": str(runtime),
                "release_root": str(tmp_path / "release"),
                "runner_home": str(tmp_path / "runner"),
                "python_executable": "python",
                "source_sha": "a" * 40,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(m, "watchdog_runtime_metadata", lambda: metadata_path)

    class FakeWatchdog:
        @staticmethod
        def cycle(installed):
            return {
                "runner_recovery_ok": True,
                "rdc_recovery_ok": False,
                "github_runner": {
                    "status": "recovered",
                    "started": True,
                },
            }

        @staticmethod
        def task_status():
            return {
                "exists": False,
                "trigger_at_startup": False,
            }

    monkeypatch.setattr(m, "_watchdog_module", lambda installed: FakeWatchdog)
    monkeypatch.setattr(
        m,
        "_activate_watchdog",
        lambda metadata: (_ for _ in ()).throw(
            AssertionError("UAC path must not run")
        ),
    )

    result = m._recover_control_plane({"release_root": str(tmp_path)})

    assert result["local_recovery_ok"] is True
    assert result["github_pickup_required"] is True
    assert result["github_pickup_proven"] is False
    assert result["cycle"]["github_runner"]["status"] == "recovered"
    assert result["activation"]["status"] == "persistence_pending"


def test_process_once_publishes_sanitized_readback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = datetime.now(timezone.utc)
    metadata = {
        "runtime_root": str(tmp_path),
        "release_root": str(tmp_path / "release"),
        "source_sha": "a" * 40,
        "not_before": (now - timedelta(seconds=30)).isoformat(),
    }
    comment = gh_comment(comment_id=301, body="/desktop-runtime admin status", created=now)
    monkeypatch.setattr(m, "fetch_comments", lambda since: [comment])
    monkeypatch.setattr(
        m,
        "execute_action",
        lambda *args, **kwargs: {
            "ok": True,
            "result": {"handler": "status"},
        },
    )
    published = []
    monkeypatch.setattr(
        m,
        "_publish_readback",
        lambda meta, accepted: published.append(dict(accepted))
        or {
            "published": True,
            "channel": "ntfy",
            "authoritative": False,
        },
    )

    result = m.process_once(metadata, reference_time=now)
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))

    assert result["commands_accepted"] == 1
    assert published[0]["comment_id"] == 301
    assert published[0]["status"] == "completed"
    assert state["readback"]["published"] is True
    assert state["readback"]["authoritative"] is False


def test_failed_command_state_does_not_persist_raw_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = datetime.now(timezone.utc)
    metadata = {
        "runtime_root": str(tmp_path),
        "release_root": str(tmp_path / "release"),
        "source_sha": "a" * 40,
        "not_before": (now - timedelta(seconds=30)).isoformat(),
    }
    comment = gh_comment(comment_id=302, body="/desktop-runtime admin status", created=now)
    monkeypatch.setattr(m, "fetch_comments", lambda since: [comment])
    monkeypatch.setattr(
        m,
        "execute_action",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("sensitive detail must not persist")
        ),
    )
    monkeypatch.setattr(
        m,
        "_publish_readback",
        lambda meta, accepted: {
            "published": False,
            "authoritative": False,
        },
    )

    m.process_once(metadata, reference_time=now)
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))

    assert state["accepted"]["status"] == "failed"
    assert state["accepted"]["error_code"] == "RuntimeError"
    assert "sensitive detail" not in json.dumps(state)


def test_user_autostart_is_hkcu_fixed_readback_and_no_shell(monkeypatch, tmp_path: Path) -> None:
    class FakeKey:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeWinreg:
        HKEY_CURRENT_USER = object()
        KEY_SET_VALUE = 1
        KEY_QUERY_VALUE = 2
        REG_SZ = 1

        def __init__(self):
            self.value = None

        def CreateKeyEx(self, root, path, reserved, access):
            assert root is self.HKEY_CURRENT_USER
            assert path == m.USER_RUN_KEY
            assert access == self.KEY_SET_VALUE | self.KEY_QUERY_VALUE
            return FakeKey()

        def SetValueEx(self, key, name, reserved, kind, value):
            assert name == m.USER_RUN_VALUE
            assert kind == self.REG_SZ
            self.value = value

        def QueryValueEx(self, key, name):
            assert name == m.USER_RUN_VALUE
            return self.value, self.REG_SZ

    fake = FakeWinreg()
    monkeypatch.setitem(m.sys.modules, "winreg", fake)
    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    python = tmp_path / "python.exe"
    launcher = tmp_path / "run.py"
    python.write_text("", encoding="utf-8")
    launcher.write_text("", encoding="utf-8")

    result = m.register_user_autostart(
        python_executable=python,
        launcher=launcher,
    )

    assert result["mode"] == "HKCU_RUN_AT_LOGON"
    assert result["readback_verified"] is True
    assert result["requires_admin"] is False
    assert str(python.resolve()) in fake.value
    assert str(launcher.resolve()) in fake.value
    source = MODULE.read_text(encoding="utf-8").casefold()
    assert "hkey_local_machine" not in source
    assert "shell=true" not in source


def test_user_broker_start_is_fixed_argv_and_not_functional_success(
    monkeypatch, tmp_path: Path
) -> None:
    calls = []

    class Proc:
        pid = 9876

        @staticmethod
        def poll():
            return None

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return Proc()

    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(m.os, "name", "nt")
    python = tmp_path / "python.exe"
    launcher = tmp_path / "run.py"
    python.write_text("", encoding="utf-8")
    launcher.write_text("", encoding="utf-8")

    result = m.start_user_broker(
        python_executable=python,
        launcher=launcher,
    )

    assert result["requested"] is True
    assert result["startup_survived"] is True
    assert result["functional_success_proven"] is False
    argv, kwargs = calls[0]
    assert argv == [str(python.resolve()), str(launcher.resolve())]
    assert kwargs["shell"] is False


def test_stage_persistent_python_copies_runtime_and_reuses_by_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-python"
    source.mkdir()
    python = source / "python.exe"
    python.write_bytes(b"python-runtime")
    (source / "python312.dll").write_bytes(b"dll")
    (source / "Lib").mkdir()
    (source / "Lib" / "os.py").write_text("# stdlib\n", encoding="utf-8")
    runtime = tmp_path / "broker-runtime"

    monkeypatch.setattr(m, "_probe_python_version", lambda executable: "3.12.10")

    first = m.stage_persistent_python(python, runtime)
    stable = Path(first["python_executable"])
    assert stable.is_file()
    assert stable.parent.parent.name == m.PERSISTED_PYTHON_DIR
    assert first["version"] == "3.12.10"
    assert first["reused"] is False
    assert m._sha256_file(stable) == m._sha256_file(python)
    assert (stable.parent / "python312.dll").is_file()
    assert (stable.parent / "Lib" / "os.py").is_file()

    second = m.stage_persistent_python(python, runtime)
    assert second["python_executable"] == stable
    assert second["reused"] is True


def test_stage_persistent_python_rejects_virtualenv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    venv = tmp_path / "venv"
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    python = scripts / "python.exe"
    python.write_bytes(b"python-runtime")
    (venv / "pyvenv.cfg").write_text("home = C:\\Python312\n", encoding="utf-8")

    with pytest.raises(m.BrokerError, match="python_virtualenv_not_persistable"):
        m.stage_persistent_python(python, tmp_path / "runtime")


def test_install_uses_persisted_python_for_hkcu_and_immediate_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in (
        "desktop_admin_broker.py",
        "desktop_admin_broker_uac_launcher.py",
        m.WATCHDOG_SCRIPT,
        m.WATCHDOG_UAC_SCRIPT,
        m.RDC_RECOVERY_SCRIPT,
        m.RUNNER_BOOTSTRAP_SCRIPT,
        m.READBACK_SCRIPT,
    ):
        (scripts / name).write_text("# stub\n", encoding="utf-8")

    original = tmp_path / "transient" / "python.exe"
    original.parent.mkdir()
    original.write_text("", encoding="utf-8")
    runtime = tmp_path / "runtime"
    stable = runtime / m.PERSISTED_PYTHON_DIR / "abcd" / "python.exe"
    stable.parent.mkdir(parents=True)
    stable.write_text("", encoding="utf-8")
    observed: list[tuple[str, Path]] = []

    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(
        m,
        "stage_persistent_python",
        lambda python_executable, runtime_root: {
            "python_executable": stable,
            "runtime_root": stable.parent,
            "version": "3.12.10",
            "executable_sha256": "a" * 64,
            "reused": False,
        },
    )
    monkeypatch.setattr(
        m,
        "register_task",
        lambda **kwargs: (_ for _ in ()).throw(
            m.BrokerError("task_scheduler_access_denied")
        ),
    )
    monkeypatch.setattr(
        m,
        "register_user_autostart",
        lambda **kwargs: observed.append(("hkcu", kwargs["python_executable"]))
        or {
            "ok": True,
            "mode": "HKCU_RUN_AT_LOGON",
            "readback_verified": True,
            "requires_admin": False,
        },
    )
    monkeypatch.setattr(
        m,
        "start_user_broker",
        lambda **kwargs: observed.append(("start", kwargs["python_executable"]))
        or {
            "requested": True,
            "pid": 1234,
            "startup_survived": True,
            "functional_success_proven": False,
        },
    )

    result = m.install(
        source,
        source_sha="b" * 40,
        python_executable=original,
        runtime_root=runtime,
        poll_seconds=90,
        confirm=m.INSTALL_CONFIRM,
    )

    assert result["activation_pending"] is True
    assert observed == [("hkcu", stable), ("start", stable)]
    metadata = json.loads((runtime / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["python_executable"] == str(stable)
    assert metadata["python_runtime"]["persistent"] is True
    assert metadata["python_runtime"]["version"] == "3.12.10"
    assert str(original) not in json.dumps(metadata)
