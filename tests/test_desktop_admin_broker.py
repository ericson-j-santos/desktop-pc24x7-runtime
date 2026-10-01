if action == "refresh-self":
            result.update(
                {
                    "refresh_state": "already_current",
                    "new_broker_started": False,
                }
            )
        return {
            "ok": True,
            "action": action,
            "comment_id": comment_id,
            "result": result,
        }

    monkeypatch.setattr(m, "execute_action", fake_execute)
    monkeypatch.setattr(
        m,
        "_publish_readback",
        lambda meta, accepted: {"published": True, "authoritative": False},
    )

    result = m.process_once(metadata, reference_time=now + timedelta(seconds=1))

    assert result["restart_requested"] is False
    assert result["commands_accepted"] == 2
    assert result["last_seen_comment_id"] == 602
    assert calls == [("refresh-self", 601), ("status", 602)]


def test_reconcile_registers_missing_physical_fallback_before_marking_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    python = tmp_path / "python.exe"
    launcher = tmp_path / "run.py"
    registered = {
        "ok": True,
        "exists": True,
        "mode": m.USER_AUTOSTART_MODE,
        "readback_verified": True,
        "requires_admin": False,
    }
    calls = []
    monkeypatch.setattr(
        m,
        "user_autostart_status",
        lambda **kwargs: {
            "ok": False,
            "exists": False,
            "mode": m.USER_AUTOSTART_MODE,
            "readback_verified": False,
            "requires_admin": False,
        },
    )
    monkeypatch.setattr(
        m,
        "register_user_autostart",
        lambda **kwargs: calls.append(kwargs) or dict(registered),
    )

    result = m._reconcile_activation_metadata(
        {
            "activation_pending": False,
            "requires_uac_activation": False,
            "admin_channel_ready": True,
        },
        python_executable=python,
        launcher=launcher,
    )

    assert len(calls) == 1
    assert result["fallback_persistence"] == registered
    assert result["fallback_start_requested"] is True
    assert result["functional_success_proven"] is False
    assert result["admin_channel_ready"] is False


def test_reconcile_does_not_demote_verified_elevated_task(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata = {
        "activation_pending": False,
        "requires_uac_activation": False,
        "admin_channel_ready": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
        "fallback_persistence": {
            "mode": m.USER_AUTOSTART_MODE,
            "readback_verified": True,
        },
    }
    monkeypatch.setattr(m, "task_status", lambda: dict(metadata["admin_task"]))
    monkeypatch.setattr(
        m,
        "user_autostart_status",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("task elevada comprovada não deve recriar HKCU")
        ),
    )

    result = m._reconcile_activation_metadata(
        metadata,
        python_executable=tmp_path / "python.exe",
        launcher=tmp_path / "run.py",
    )

    assert result == metadata
    assert result is not metadata


def test_reconcile_demotes_stale_elevated_proof_when_physical_task_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fallback = {
        "ok": True,
        "exists": True,
        "mode": m.USER_AUTOSTART_MODE,
        "value_name": m.USER_RUN_VALUE,
        "readback_verified": True,
        "requires_admin": False,
    }
    metadata = {
        "activation_pending": False,
        "requires_uac_activation": False,
        "admin_channel_ready": True,
        "functional_success_proven": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
        "fallback_persistence": dict(fallback),
    }
    monkeypatch.setattr(
        m,
        "task_status",
        lambda: {"exists": False, "trigger_at_startup": False},
    )
    monkeypatch.setattr(m, "user_autostart_status", lambda **kwargs: dict(fallback))
    monkeypatch.setattr(
        m,
        "register_user_autostart",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("HKCU válido não deve ser regravado")
        ),
    )

    result = m._reconcile_activation_metadata(
        metadata,
        python_executable=tmp_path / "python.exe",
        launcher=tmp_path / "run.py",
    )

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
