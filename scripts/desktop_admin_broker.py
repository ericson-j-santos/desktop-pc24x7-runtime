aise BrokerError(f"registro do broker falhou: {type(exc).__name__}") from exc
    return {
        "ok": True,
        "task_name": TASK_NAME,
        "trigger": "AtStartup",
        "logon_type": "S4U",
        "run_level": "highest",
        "password_used": False,
    }


def task_status() -> dict[str, Any]:
    try:
        service = _scheduler()
        folder = service.GetFolder(TASK_FOLDER)
        task = folder.GetTask(TASK_LEAF)
        definition = task.Definition
        trigger_at_startup = any(
            definition.Triggers.Item(i).Type == TASK_TRIGGER_BOOT
            for i in range(1, definition.Triggers.Count + 1)
        )
        return {
            "exists": True,
            "trigger_at_startup": trigger_at_startup,
            "logon_type": "S4U" if definition.Principal.LogonType == TASK_LOGON_S4U else str(definition.Principal.LogonType),
            "run_level": "highest" if definition.Principal.RunLevel == TASK_RUNLEVEL_HIGHEST else str(definition.Principal.RunLevel),
            "enabled": bool(task.Enabled),
        }
    except Exception:
        return {"exists": False, "trigger_at_startup": False}


def run_task() -> dict[str, Any]:
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    schtasks = root / "System32" / "schtasks.exe"
    completed = subprocess.run(
        [str(schtasks), "/Run", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise BrokerError("falha ao iniciar tarefa do broker")
    return {"run_returncode": completed.returncode}


def _copy_release(source_root: Path, release_root: Path) -> None:
    scripts = release_root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    for name in (
        "desktop_admin_broker.py",
        "desktop_admin_broker_uac_launcher.py",
        WATCHDOG_SCRIPT,
        WATCHDOG_UAC_SCRIPT,
        RDC_RECOVERY_SCRIPT,
        RUNNER_BOOTSTRAP_SCRIPT,
        READBACK_SCRIPT,
    ):
        source = source_root / "scripts" / name
        if not source.is_file():
            raise BrokerError(f"script obrigatório ausente: {name}")
        destination = scripts / name
        destination.write_bytes(source.read_bytes())


def _write_launcher(runtime_root: Path) -> Path:
    launcher = runtime_root / "run.py"
    launcher.write_text(
        "from pathlib import Path\n"
        "import json, runpy, sys\n"
        "metadata = Path(__file__).with_name('metadata.json')\n"
        "payload = json.loads(metadata.read_text(encoding='utf-8'))\n"
        "script = Path(payload['release_root']) / 'scripts' / 'desktop_admin_broker.py'\n"
        "sys.argv = [str(script), 'watch', '--metadata', str(metadata)]\n"
        "runpy.run_path(str(script), run_name='__main__')\n",
        encoding="utf-8",
    )
    return launcher


def _write_uac_activation_launcher(
    runtime_root: Path,
    *,
    release_root: Path,
    python_executable: Path,
    metadata_path: Path,
) -> Path:
    launcher = runtime_root / "Activate-Desktop-Admin-Broker.cmd"
    uac_script = release_root / "scripts" / "desktop_admin_broker_uac_launcher.py"
    command = subprocess.list2cmdline(
        [
            str(python_executable),
            str(uac_script),
            "--metadata",
            str(metadata_path),
            "--confirm",
            "LAUNCH-DESKTOP-ADMIN-BROKER-UAC",
            "--timeout-seconds",
            "90",
        ]
    )
    launcher.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8")
    return launcher


def load_installed_metadata(metadata_path: Path, *, require_current_release: bool = False) -> dict[str, Any]:
    metadata_path = metadata_path.resolve()
    if not metadata_path.is_file():
        raise BrokerError("metadata do broker ausente")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    runtime_root = Path(str(metadata.get("runtime_root") or "")).resolve()
    release_root = Path(str(metadata.get("release_root") or "")).resolve()
    source_sha = validate_sha(str(metadata.get("source_sha") or ""))
    if metadata_path != runtime_root / "metadata.json":
        raise BrokerError("metadata fora do runtime governado")
    if os.name == "nt" and runtime_root != default_runtime_root().resolve():
        raise BrokerError("runtime_root fora do caminho governado")
    expected_release = runtime_root / "releases" / source_sha
    if release_root != expected_release:
        raise BrokerError("release_root não corresponde ao source_sha")
    release_broker = release_root / "scripts" / "desktop_admin_broker.py"
    launcher = runtime_root / "run.py"
    python_executable = Path(str(metadata.get("python_executable") or "")).resolve()
    for path in (release_broker, launcher, python_executable):
        if not path.is_file():
            raise BrokerError(f"arquivo instalado ausente: {path.name}")
    if require_current_release and release_broker.resolve() != Path(__file__).resolve():
        raise BrokerError("subcomando elevado deve executar da release imutável")
    return {
        "metadata": metadata,
        "metadata_path": metadata_path,
        "runtime_root": runtime_root,
        "release_root": release_root,
        "release_broker": release_broker,
        "launcher": launcher,
        "python_executable": python_executable,
    }


def register_task_from_metadata(metadata_path: Path) -> dict[str, Any]:
    installation = load_installed_metadata(metadata_path, require_current_release=True)
    register_task(
        python_executable=installation["python_executable"],
        launcher=installation["launcher"],
    )
    observed = task_status()
    ready = (
        observed.get("exists") is True
        and observed.get("trigger_at_startup") is True
        and str(observed.get("logon_type") or "").casefold() == "s4u"
        and str(observed.get("run_level") or "").casefold() == "highest"
    )
    if not ready:
        raise BrokerError("task_registration_readback_failed")
    started = run_task()
    metadata = dict(installation["metadata"])
    metadata.update(
        {
            "activation_pending": False,
            "requires_uac_activation": False,
            "admin_channel_ready": True,
            "admin_task": observed,
            "admin_task_start": started,
            "uac_activated_at": now_iso(),
        }
    )
    atomic_json(installation["metadata_path"], metadata)
    remove_user_autostart()
    return {"ok": True, "task": observed, "start": started, "metadata_updated": True}


def install(
    source_root: Path,
    *,
    source_sha: str,
    python_executable: Path,
    runtime_root: Path | None,
    poll_seconds: int,
    confirm: str,
) -> dict[str, Any]:
    if confirm != INSTALL_CONFIRM:
        raise BrokerError("confirmação inválida")
    host = require_windows_desktop()
    sha = validate_sha(source_sha)
    runtime = (runtime_root or default_runtime_root()).resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    persistent_python = stage_persistent_python(
        python_executable.resolve(),
        runtime,
    )
    stable_python = Path(persistent_python["python_executable"])
    release = runtime / "releases" / sha
    _copy_release(source_root.resolve(), release)
    launcher = _write_launcher(runtime)
    metadata_path = runtime / "metadata.json"
    activation_launcher = _write_uac_activation_launcher(
        runtime,
        release_root=release,
        python_executable=stable_python,
        metadata_path=metadata_path,
    )
    metadata = {
        "schema_version": "1",
        "service": "reqsys-desktop-admin-broker",
        "host": host,
        "source_sha": sha,
        "runtime_root": str(runtime),
        "release_root": str(release),
        "python_executable": str(stable_python),
        "python_runtime": {
            "persistent": True,
            "version": persistent_python["version"],
            "executable_sha256": persistent_python["executable_sha256"],
            "reused": persistent_python["reused"],
        },
        "poll_seconds": DEFAULT_POLL_SECONDS,
        "not_before": now_iso(),
        "repository": REPOSITORY,
        "issue_number": ISSUE_NUMBER,
        "expected_actor": EXPECTED_ACTOR,
        "activation_pending": False,
        "requires_uac_activation": False,
        "production_touched": False,
        "secrets_read": False,
        "installed_at": now_iso(),
        "activation_launcher": str(activation_launcher),
    }
    atomic_json(metadata_path, metadata)
    activation_pending = False
    user_autostart = None
    started = None
    try:
        task = register_task(python_executable=stable_python, launcher=launcher)
    except BrokerError as exc:
        if str(exc) != "task_scheduler_access_denied":
            raise
        activation_pending = True
        task = {"exists": False, "error": "access_denied"}
        user_autostart = register_user_autostart(
            python_executable=stable_python,
            launcher=launcher,
        )
        metadata.update(
            {
                "activation_pending": True,
                "requires_uac_activation": True,
                "fallback_persistence": user_autostart,
                "fallback_start_requested": True,
            }
        )
        atomic_json(metadata_path, metadata)
        started = start_user_broker(
            python_executable=stable_python,
            launcher=launcher,
        )
    if not activation_pending:
        started = run_task()
    return {
        "ok": True,
        "activation_pending": activation_pending,
        "requires_uac_activation": activation_pending,
        "task": task,
        "user_autostart": user_autostart,
        "start": started,
        "functional_success_proven": False if activation_pending else None,
        "metadata_path": str(metadata_path),
        "activation_launcher": str(activation_launcher),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    install_p = sub.add_parser("install")
    install_p.add_argument("--source-root", type=Path, required=True)
    install_p.add_argument("--source-sha", required=True)
    install_p.add_argument("--python-executable", type=Path, default=Path(sys.executable))
    install_p.add_argument("--runtime-root", type=Path)
    install_p.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    install_p.add_argument("--confirm", required=True)

    watch_p = sub.add_parser("watch")
    watch_p.add_argument("--metadata", type=Path, required=True)

    once_p = sub.add_parser("once")
    once_p.add_argument("--metadata", type=Path, required=True)

    register_p = sub.add_parser("register-task-com")
    register_p.add_argument("--metadata", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "install":
            payload = install(
                args.source_root,
                source_sha=args.source_sha,
                python_executable=args.python_executable,
                runtime_root=args.runtime_root,
                poll_seconds=args.poll_seconds,
                confirm=args.confirm,
            )
        elif args.command == "watch":
            return watch(args.metadata.resolve())
        elif args.command == "once":
            metadata = load_installed_metadata(args.metadata.resolve())["metadata"]
            payload = process_once(metadata)
        else:
            payload = register_task_from_metadata(args.metadata.resolve())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:1000], "error_type": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
