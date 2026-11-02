

    assert result["activation_pending"] is True
    assert result["requires_uac_activation"] is True
    assert result["fallback_start_requested"] is True
    assert result["functional_success_proven"] is False
    assert result["admin_channel_ready"] is False
    assert result["fallback_persistence"] == fallback


def test_broker_lock_serializes_two_instances_and_allows_handoff(tmp_path: Path) -> None:
    first = m._acquire_broker_lock(tmp_path, timeout_seconds=0)
    try:
        with pytest.raises(m.BrokerError, match="broker_lock_timeout"):
            m._acquire_broker_lock(tmp_path, timeout_seconds=0)
    finally:
        m._release_broker_lock(first)

    successor = m._acquire_broker_lock(tmp_path, timeout_seconds=0)
    m._release_broker_lock(successor)


def test_degraded_watch_releases_lock_before_admin_successor_fetches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    degraded = {
        "runtime_root": str(tmp_path),
        "admin_channel_ready": False,
    }
    ready = {
        "runtime_root": str(tmp_path),
        "admin_channel_ready": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
    }
    payloads = iter(
        [
            {
                "runtime_root": tmp_path,
                "python_executable": tmp_path / "python.exe",
                "launcher": tmp_path / "run.py",
            },
            {"metadata": degraded},
            {"metadata": ready},
        ]
    )
    lock = object()
    released = []
    monkeypatch.setattr(m, "load_installed_metadata", lambda path: next(payloads))
    monkeypatch.setattr(m, "_acquire_broker_lock", lambda runtime_root: lock)
    monkeypatch.setattr(m, "_release_broker_lock", lambda handle: released.append(handle))
    monkeypatch.setattr(m, "task_status", lambda: dict(ready["admin_task"]))
    monkeypatch.setattr(
        m,
        "process_once",
        lambda metadata: (_ for _ in ()).throw(
            AssertionError("fallback degradado deve sair antes de novo fetch")
        ),
    )

    assert m.watch(tmp_path / "metadata.json") == 0
    assert released == [lock]


def test_watch_repairs_initial_stale_green_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stale_green = {
        "runtime_root": str(tmp_path),
        "poll_seconds": 30,
        "admin_channel_ready": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
    }
    repaired = {
        **stale_green,
        "activation_pending": True,
        "requires_uac_activation": True,
        "admin_channel_ready": False,
    }
    installation = {
        "runtime_root": tmp_path,
        "python_executable": tmp_path / "python.exe",
        "launcher": tmp_path / "run.py",
    }
    loads = iter(
        [
            installation,
            {"metadata": dict(stale_green)},
            {"metadata": dict(stale_green)},
        ]
    )
    reconciled = []
    lock = object()
    released = []
    monkeypatch.setattr(m, "load_installed_metadata", lambda path: next(loads))
    monkeypatch.setattr(m, "_acquire_broker_lock", lambda runtime_root: lock)
    monkeypatch.setattr(m, "_release_broker_lock", lambda handle: released.append(handle))
    monkeypatch.setattr(
        m,
        "task_status",
        lambda: {
            "exists": False,
            "trigger_at_startup": False,
            "logon_type": None,
            "run_level": None,
            "enabled": False,
        },
    )
    monkeypatch.setattr(
        m,
        "_reconcile_activation_metadata_file",
        lambda *args, **kwargs: reconciled.append(kwargs) or dict(repaired),
    )
    monkeypatch.setattr(m, "process_once", lambda metadata: {"restart_requested": True})

    assert m.watch(tmp_path / "metadata.json") == 0
    assert len(reconciled) == 1
    assert reconciled[0]["python_executable"] == installation["python_executable"]
    assert reconciled[0]["launcher"] == installation["launcher"]
    assert released == [lock]


def test_persist_task_activation_preserves_refreshed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata_path = tmp_path / "metadata.json"
    latest = {
        "runtime_root": str(tmp_path),
        "source_sha": "b" * 40,
        "release_root": str(tmp_path / "releases" / ("b" * 40)),
        "previous_source_sha": "a" * 40,
        "activation_pending": True,
    }
    task = {
        "exists": True,
        "trigger_at_startup": True,
        "logon_type": "S4U",
        "run_level": "highest",
        "enabled": True,
    }
    written = {}
    lock = object()
    released = []
    monkeypatch.setattr(
        m,
        "load_installed_metadata",
        lambda path, require_current_release=False: {"metadata": dict(latest)},
    )
    monkeypatch.setattr(m, "_acquire_metadata_lock", lambda path: lock)
    monkeypatch.setattr(m, "_release_broker_lock", lambda handle: released.append(handle))
    monkeypatch.setattr(
        m,
        "atomic_json",
        lambda path, payload: written.update({"path": path, "payload": dict(payload)}),
    )
    monkeypatch.setattr(m, "remove_user_autostart", lambda: None)

    result = m.persist_task_activation(
        metadata_path,
        observed=task,
        started={"run_returncode": 0},
    )

    assert result["source_sha"] == "b" * 40
    assert result["release_root"] == latest["release_root"]
    assert result["previous_source_sha"] == "a" * 40
    assert result["admin_channel_ready"] is True
    assert written["payload"] == result
    assert released == [lock]


def test_lock_contention_rejects_unexpected_os_error() -> None:
    assert m._lock_contention(OSError(errno.EIO, "io failure")) is False


def test_admin_successor_reloads_metadata_after_lock_and_continues(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ready = {
        "runtime_root": str(tmp_path),
        "poll_seconds": 30,
        "admin_channel_ready": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
    }
    loads = []
    lock = object()
    released = []

    def fake_load(path):
        loads.append(path)
        return {
            "runtime_root": tmp_path,
            "python_executable": tmp_path / "python.exe",
            "launcher": tmp_path / "run.py",
            "metadata": dict(ready),
        }

    monkeypatch.setattr(m, "load_installed_metadata", fake_load)
    monkeypatch.setattr(m, "_acquire_broker_lock", lambda runtime_root: lock)
    monkeypatch.setattr(m, "_release_broker_lock", lambda handle: released.append(handle))
    monkeypatch.setattr(m, "task_status", lambda: dict(ready["admin_task"]))
    monkeypatch.setattr(
        m,
        "process_once",
        lambda metadata: {"restart_requested": True},
    )

    assert m.watch(tmp_path / "metadata.json") == 0
    assert len(loads) == 3
    assert released == [lock]


def test_user_launcher_is_a_restartable_supervisor(tmp_path: Path) -> None:
    launcher = m._write_launcher(tmp_path)
    source = launcher.read_text(encoding="utf-8")
    assert "while True:" in source
    assert "runpy.run_path" in source
    assert "supervisor_retrying" in source
    assert "broker-heartbeat.json" in source
    assert "production_touched" in source
    assert "secrets_read" in source
    assert "reboot_performed" in source


def test_broker_heartbeat_freshness_is_bounded() -> None:
    now = datetime.now(timezone.utc)
    fresh = {
        "updated_at": now.isoformat(),
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
    }
    stale = {
        **fresh,
        "updated_at": (now - timedelta(seconds=91)).isoformat(),
    }
    assert m._heartbeat_is_fresh(fresh, reference_time=now) is True
    assert m._heartbeat_is_fresh(stale, reference_time=now) is False


def test_status_exposes_runtime_readiness_without_promoting_uac_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(m, "watchdog_runtime_metadata", lambda: tmp_path / "missing.json")
    monkeypatch.setattr(m, "task_status", lambda: {"exists": False})
    metadata = {
        "runtime_root": str(tmp_path),
        "requires_uac_activation": True,
        "admin_channel_ready": False,
        "fallback_persistence": {"mode": m.USER_AUTOSTART_MODE, "readback_verified": True},
    }
    result = m._status(metadata)
    assert result["broker_runtime"]["ready"] is False
    assert result["broker_runtime"]["admin_activation_pending"] is True
    assert result["broker_runtime"]["admin_channel_ready"] is False
    assert result["broker_runtime"]["fallback_autostart"]["readback_verified"] is True
def test_legacy_release_starts_without_staged_host_policy(tmp_path: Path) -> None:
    """The previously deployed copier omitted a now-imported module."""
    import os
    import sys
    staged = tmp_path / "legacy_release" / "scripts"
    staged.mkdir(parents=True)
    (staged / "desktop_admin_broker.py").write_bytes(MODULE.read_bytes())
    assert not (staged / "pc24x7_host_policy.py").exists()
    result = subprocess.run(
        [sys.executable, "-I", str(staged / "desktop_admin_broker.py"), "--help"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": ""},
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0, result.stderr[-250:]
    assert "ModuleNotFoundError" not in result.stderr
    assert not (staged / "pc24x7_host_policy.py").exists()


def test_pinned_host_identity_does_not_require_external_policy(monkeypatch) -> None:
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: "desktop-pdqk954")
    assert m.require_windows_desktop() == "desktop-pdqk954"


@pytest.mark.parametrize("host", ["DESKTOP-RP23OGS", "NOTERI", "UNKNOWN-HOST"])
def test_broker_rejects_other_hosts_even_if_generic_policy_knows_them(monkeypatch, host):
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: host)
    with pytest.raises(m.BrokerError, match="host não autorizado"):
        m.require_windows_desktop()


def test_release_manifest_copies_host_policy_for_watchdog_and_runner(tmp_path: Path) -> None:
    import shutil
    src = tmp_path / "source" / "scripts"
    src.mkdir(parents=True)
    manifest = ("desktop_admin_broker.py", "desktop_admin_broker_uac_launcher.py",
                m.WATCHDOG_SCRIPT, m.WATCHDOG_UAC_SCRIPT,
                m.RDC_RECOVERY_SCRIPT, m.RUNNER_BOOTSTRAP_SCRIPT,
                m.READBACK_SCRIPT, "pc24x7_host_policy.py")
    for name in manifest:
        shutil.copyfile(ROOT / "scripts" / name, src / name)
    target = tmp_path / "releases" / ("a" * 40)
    m._copy_release(src.parent, target)
    staged = target / "scripts"
    assert {path.name for path in staged.iterdir()} == set(manifest)
    assert (staged / "pc24x7_host_policy.py").read_bytes() == (src / "pc24x7_host_policy.py").read_bytes()


def test_missing_manifest_dependency_fails_closed(tmp_path: Path) -> None:
    src = tmp_path / "source" / "scripts"
    src.mkdir(parents=True)
    for name in ("desktop_admin_broker.py", "desktop_admin_broker_uac_launcher.py",
                 m.WATCHDOG_SCRIPT, m.WATCHDOG_UAC_SCRIPT,
                 m.RDC_RECOVERY_SCRIPT, m.RUNNER_BOOTSTRAP_SCRIPT, m.READBACK_SCRIPT):
        (src / name).write_text("# fixture\n", encoding="utf-8")
    with pytest.raises(m.BrokerError, match="script obrigatório ausente: pc24x7_host_policy.py"):
        m._copy_release(src.parent, tmp_path / "release")
