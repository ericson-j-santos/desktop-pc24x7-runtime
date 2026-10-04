#!/usr/bin/env python3
"""Supervisor Pareto do runtime físico PC24x7.

Executa sondas declarativas, aplica recuperações estritamente allowlisted e abre
o circuit breaker quando tentativas repetidas não alteram a precondição.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

EXPECTED_HOST = "DESKTOP-PDQK954"
STATUS_OK = "ok"
STATUS_INFRA_UNAVAILABLE = "INFRA_UNAVAILABLE"
ALLOWED_KINDS = {"runner", "http", "docker"}


class SupervisorError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SupervisorError(f"JSON invalido: {path}")
    return value


def validate_config(config: dict[str, Any]) -> None:
    if config.get("host") != EXPECTED_HOST:
        raise SupervisorError("host configurado nao autorizado")
    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SupervisorError("targets deve ser uma lista nao vazia")
    names: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise SupervisorError("target invalido")
        name = target.get("name")
        kind = target.get("kind")
        if not isinstance(name, str) or not name or name in names:
            raise SupervisorError("nome de target ausente ou duplicado")
        if kind not in ALLOWED_KINDS:
            raise SupervisorError(f"tipo de target nao autorizado: {kind}")
        if any(key in target for key in ("command", "shell", "executable")):
            raise SupervisorError("comandos arbitrarios sao proibidos")
        names.add(name)


def run_command(args: list[str], timeout: float = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


def probe_http(url: str, timeout: float = 5) -> dict[str, Any]:
    if not url.startswith("http://127.0.0.1:"):
        raise SupervisorError("probe HTTP deve usar loopback")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read(65536)
            healthy = 200 <= response.status < 300
            return {"healthy": healthy, "status_code": response.status, "bytes": len(body)}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"healthy": False, "reason": type(exc).__name__}


def probe_docker(container: str, runner: Callable[..., subprocess.CompletedProcess[str]]) -> dict[str, Any]:
    result = runner(
        ["docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", container],
        timeout=20,
    )
    if result.returncode != 0:
        return {"healthy": False, "reason": "container_missing_or_docker_unavailable"}
    status, _, health = result.stdout.strip().partition("|")
    healthy = status == "running" and health in ("", "healthy")
    return {"healthy": healthy, "container_status": status, "health_status": health or None}


def probe_runner(runner_home: Path) -> dict[str, Any]:
    from desktop_control_plane_watchdog import runner_process_snapshot, validate_runner_home

    root = validate_runner_home(runner_home)
    snapshot = runner_process_snapshot(root)
    return {"healthy": len(snapshot["matching_pids"]) == 1, "listener_count": len(snapshot["matching_pids"])}


def probe_target(target: dict[str, Any], command_runner=run_command) -> dict[str, Any]:
    kind = target["kind"]
    if kind == "http":
        return probe_http(str(target["url"]), float(target.get("timeout_seconds", 5)))
    if kind == "docker":
        return probe_docker(str(target["container"]), command_runner)
    if kind == "runner":
        return probe_runner(Path(os.path.expandvars(str(target["runner_home"]))))
    raise SupervisorError(f"tipo nao suportado: {kind}")


def recover_target(target: dict[str, Any], command_runner=run_command) -> dict[str, Any]:
    kind = target["kind"]
    if kind == "runner":
        from desktop_control_plane_watchdog import start_runner

        root = Path(os.path.expandvars(str(target["runner_home"])))
        log_path = Path(os.path.expandvars(str(target["log_path"])))
        return {"action": "start_runner", **start_runner(root, log_path)}
    if kind == "docker":
        result = command_runner(["docker", "restart", str(target["container"])], timeout=60)
        return {"action": "restart_container", "exit_code": result.returncode}
    if kind == "http" and target.get("recovery_task"):
        result = command_runner(
            ["schtasks.exe", "/Run", "/TN", str(target["recovery_task"])], timeout=30
        )
        return {"action": "run_scheduled_task", "exit_code": result.returncode}
    return {"action": "none", "exit_code": 1}


def _breaker_open(entry: dict[str, Any], now: float, cooldown: int) -> bool:
    opened_at = float(entry.get("opened_at_epoch", 0) or 0)
    return opened_at > 0 and now - opened_at < cooldown


def run_cycle(
    config: dict[str, Any],
    state: dict[str, Any],
    *,
    apply: bool,
    epoch: float | None = None,
    probe_fn=probe_target,
    recover_fn=recover_target,
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_config(config)
    now = time.time() if epoch is None else epoch
    max_attempts = int(config.get("max_attempts", 3))
    cooldown = int(config.get("cooldown_seconds", 900))
    target_state = state.setdefault("targets", {})
    results: list[dict[str, Any]] = []

    for target in config["targets"]:
        name = target["name"]
        entry = target_state.setdefault(name, {"attempts": 0, "opened_at_epoch": 0})
        probe = probe_fn(target)
        item: dict[str, Any] = {"name": name, "kind": target["kind"], "probe": probe}
        if probe.get("healthy") is True:
            entry.update({"attempts": 0, "opened_at_epoch": 0, "last_healthy_at": now_iso()})
            item["status"] = STATUS_OK
        elif _breaker_open(entry, now, cooldown):
            item.update({"status": STATUS_INFRA_UNAVAILABLE, "reason": "circuit_breaker_open"})
        elif int(entry.get("attempts", 0)) >= max_attempts:
            entry["opened_at_epoch"] = now
            item.update({"status": STATUS_INFRA_UNAVAILABLE, "reason": "attempt_limit_reached"})
        elif apply:
            recovery = recover_fn(target)
            entry["attempts"] = int(entry.get("attempts", 0)) + 1
            entry["last_attempt_at"] = now_iso()
            item.update({"status": STATUS_INFRA_UNAVAILABLE, "reason": "recovery_attempted", "recovery": recovery})
        else:
            item.update({"status": STATUS_INFRA_UNAVAILABLE, "reason": "recovery_required"})
        results.append(item)

    overall = STATUS_OK if all(item["status"] == STATUS_OK for item in results) else STATUS_INFRA_UNAVAILABLE
    evidence = {
        "schema_version": 1,
        "timestamp": now_iso(),
        "host": socket.gethostname(),
        "status": overall,
        "apply": apply,
        "targets": results,
    }
    state["updated_at"] = evidence["timestamp"]
    state["status"] = overall
    return evidence, state


def main() -> int:
    parser = argparse.ArgumentParser(description="Supervisor de saude do Desktop PC24x7")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        raise SupervisorError("execucao permitida somente no host governado")
    config = load_json(args.config)
    state = load_json(args.state)
    evidence, state = run_cycle(config, state, apply=args.apply)
    atomic_json(args.state, state)
    atomic_json(args.evidence, evidence)
    print(json.dumps(evidence, sort_keys=True, ensure_ascii=True))
    return 0 if evidence["status"] == STATUS_OK else 2


if __name__ == "__main__":
    raise SystemExit(main())
