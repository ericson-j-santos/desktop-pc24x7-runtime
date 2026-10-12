"""Disposable, process-backed service cutover rehearsal for Desktop DEV.

All subprocesses run an embedded constant HTTP fixture created inside a fresh
temporary directory. No live supervisor, runner, database, Startup, port 8787,
service manager, or installed runtime is accessed or modified.

This is NOT an authorized real cutover or proof of Windows service rollback.
"""
from __future__ import annotations

import argparse
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

if __package__:
    from . import desktop_orchestrator_cutover_model as transaction
else:
    import desktop_orchestrator_cutover_model as transaction

CONFIRM = "VERIFY-ISOLATED-ORCHESTRATOR-SERVICE-CYCLE"
REPO = "ericson-j-santos/desktop-pc24x7-runtime"
RUNNER = "DESKTOP-PDQK954-runtime"
SCENARIOS = (
    "success",
    "startup_exit",
    "readiness_timeout",
    "crash_after_health",
    "wrong_process_identity",
    "postcondition_failure",
)

# Entire child program is constant. No arbitrary executable/URL/path input.
FIXTURE = r'''from __future__ import annotations
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import sys
import time

p=argparse.ArgumentParser()
p.add_argument("--port",type=int,required=True)
p.add_argument("--runtime-sha",required=True)
p.add_argument("--nonce",required=True)
p.add_argument("--behavior",choices=("ready","exit","hang","crash"),required=True)
a=p.parse_args()
if a.behavior=="exit": sys.exit(19)
if a.behavior=="hang":
    time.sleep(30)
    sys.exit(20)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        if self.path not in ("/readyz","/healthz"):
            self.send_error(404); return
        obj={"ready": True, "ok": True, "runtime_sha": a.runtime_sha,
             "pid": os.getpid(), "nonce": a.nonce}
        payload=json.dumps(obj,sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        if a.behavior=="crash" and self.path=="/healthz":
            os._exit(29)
with HTTPServer(("127.0.0.1",a.port), Handler) as service:
    service.serve_forever(poll_interval=0.1)
'''


class ServiceCycleError(ValueError):
    pass


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _readback(port: int, path: str) -> dict[str, Any] | None:
    if path not in ("/healthz", "/readyz"):
        raise ServiceCycleError("PROBE_PATH_NOT_ALLOWED")
    con = HTTPConnection("127.0.0.1", port, timeout=0.7)
    try:
        con.request("GET", path, headers={"Cache-Control": "no-store"})
        response = con.getresponse()
        raw = response.read(2049)
        if response.status != 200 or len(raw) > 2048:
            return None
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, HTTPException):
        return None
    finally:
        con.close()


def _safe_env() -> dict[str, str]:
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE",
            "LOCALAPPDATA", "APPDATA", "PYTHONIOENCODING"}
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


class ShadowChild:
    """Owns one disposable subprocess. Never reads/kills another PID."""

    def __init__(self, *, script: Path, runtime_sha: str, behavior: str = "ready"):
        self.script = script
        self.runtime_sha = runtime_sha
        self.behavior = behavior
        self.port = _port()
        self.nonce = os.urandom(16).hex()
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        if (self.process is not None or self.script.name != "cycle-server.py"
            or self.script.is_symlink() or not self.script.is_file()
            or self.runtime_sha not in (transaction.OLD_SHA, transaction.TARGET_SHA)
            or self.behavior not in ("ready", "exit", "hang", "crash")):
            raise ServiceCycleError("CHILD_START_CONTRACT_INVALID")
        args = [sys.executable, "-B", "-u", str(self.script), "--port", str(self.port),
                "--runtime-sha", self.runtime_sha, "--nonce", self.nonce,
                "--behavior", self.behavior]
        try:
            self.process = subprocess.Popen(
                args, cwd=self.script.parent, shell=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=_safe_env(),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError:
            raise ServiceCycleError("CHILD_START_BLOCKED") from None

    def verify(self, *, timeout: float = 3, wrong_identity: bool = False) -> None:
        if self.process is None or not (0.2 <= timeout <= 5):
            raise ServiceCycleError("CHILD_VERIFY_CONTRACT_INVALID")
        deadline = time.monotonic() + timeout
        expected_nonce = ("0" * 32 if wrong_identity else self.nonce)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ServiceCycleError("CHILD_EXITED_BEFORE_READINESS")
            ready = _readback(self.port, "/readyz")
            health = _readback(self.port, "/healthz")
            if ready is not None or health is not None:
                for record in (ready, health):
                    if (not isinstance(record, dict)
                        or record.get("runtime_sha") != self.runtime_sha
                        or record.get("pid") != self.process.pid
                        or record.get("nonce") != expected_nonce
                        or record.get("ready") is not True
                        or record.get("ok") is not True):
                        raise ServiceCycleError("CHILD_INDEPENDENT_IDENTITY_INVALID")
                # Detect a process that became healthy and then immediately died.
                time.sleep(0.16)
                if self.process.poll() is not None:
                    raise ServiceCycleError("CHILD_CRASHED_AFTER_READINESS")
                return
            time.sleep(0.07)
        raise ServiceCycleError("CHILD_READINESS_TIMEOUT")

    def stop(self) -> None:
        owned = self.process
        if owned is None:
            return
        if owned.poll() is None:
            owned.terminate()
        try:
            owned.wait(timeout=3)
        except subprocess.TimeoutExpired:
            owned.kill()  # Only this instance's Popen handle, never a live service PID.
            owned.wait(timeout=3)
        if owned.poll() is None:
            raise ServiceCycleError("OWNED_CHILD_STILL_RUNNING")

    @property
    def stopped(self) -> bool:
        return self.process is None or self.process.poll() is not None


def _write_release(home: Path, name: str, sha: str) -> None:
    stage = home / name
    stage.mkdir()
    (stage / "runtime-version.json").write_text(
        json.dumps({"schema_version": 1, "source_sha": sha}), encoding="utf-8")
    (stage / "code-proof.txt").write_text(
        "isolated-release-" + sha, encoding="utf-8")


def rehearse(scenario: str, *, correlation_id: str) -> dict[str, Any]:
    """Start old -> stop old -> test new -> rollback old or replay new, in TEMP."""
    if scenario not in SCENARIOS:
        raise ServiceCycleError("SCENARIO_NOT_ALLOWED")
    if not transaction.APPROVAL_RE.fullmatch(correlation_id):
        raise ServiceCycleError("CORRELATION_INVALID")
    children: list[ShadowChild] = []
    old_recovered = False
    target_verified = False
    replay_verified = False
    outcome = ""
    with tempfile.TemporaryDirectory(prefix="orch-owned-cycle-") as tmp:
        home = Path(tmp)
        (home / transaction.SIMULATION_MARKER).write_text(
            transaction.SIMULATION_VALUE, encoding="utf-8")
        _write_release(home, "active", transaction.OLD_SHA)
        _write_release(home, "candidate", transaction.TARGET_SHA)
        program = home / "cycle-server.py"
        program.write_text(FIXTURE, encoding="utf-8")

        def spawn(sha: str, mode: str = "ready") -> ShadowChild:
            child = ShadowChild(script=program, runtime_sha=sha, behavior=mode)
            children.append(child)
            child.start()
            return child

        def health(target_sha: str) -> dict[str, Any]:
            nonlocal target_verified
            if target_sha != transaction.TARGET_SHA:
                raise ServiceCycleError("NEW_SHA_UNEXPECTED")
            old.stop()
            behavior = {
                "startup_exit": "exit",
                "readiness_timeout": "hang",
                "crash_after_health": "crash",
            }.get(scenario, "ready")
            candidate = spawn(transaction.TARGET_SHA, behavior)
            candidate.verify(
                timeout=0.65 if scenario == "readiness_timeout" else 3,
                wrong_identity=scenario == "wrong_process_identity",
            )
            target_verified = True
            return {
                "ready": scenario != "postcondition_failure",
                "runtime_sha": target_sha,
                # Synthetic process-instance signal only; not a real worker ID.
                "worker_instance_changed": candidate.process.pid != old.process.pid,
            }

        try:
            old = spawn(transaction.OLD_SHA)
            old.verify()
            try:
                result = transaction.simulate_transaction(
                    home, correlation_id=correlation_id, health=health
                )
                if scenario != "success" or result["result"] != "SIMULATED_SWITCH_COMMITTED":
                    raise ServiceCycleError("UNEXPECTED_COMMIT")
                candidate = children[-1]
                candidate.verify()
                again = transaction.simulate_transaction(
                    home, correlation_id=correlation_id,
                    health=lambda _sha: (_ for _ in ()).throw(
                        ServiceCycleError("REPLAY_RESTART_FORBIDDEN")),
                )
                if again.get("replayed") is not True:
                    raise ServiceCycleError("REPLAY_NOT_IDEMPOTENT")
                replay_verified = True
                if transaction._read_sha(home / "active") != transaction.TARGET_SHA:
                    raise ServiceCycleError("COMMITTED_SHA_INVALID")
                outcome = "ISOLATED_PROCESS_SWITCH_AND_REPLAY_VERIFIED"
            except transaction.CutoverFailure as exc:
                if scenario == "success" or not exc.restored:
                    raise ServiceCycleError("ROLLBACK_NOT_VERIFIED") from None
                if transaction._read_sha(home / "active") != transaction.OLD_SHA:
                    raise ServiceCycleError("RESTORED_RELEASE_SHA_INVALID")
                for child in children:
                    child.stop()
                restored = spawn(transaction.OLD_SHA)
                restored.verify()
                if (transaction._read_sha(home / "candidate") != transaction.TARGET_SHA
                    or (home / "previous").exists()
                    or (home / ".transaction.lock").exists()):
                    raise ServiceCycleError("RESTORED_RELEASE_LAYOUT_INVALID")
                old_recovered = True
                outcome = "ISOLATED_PROCESS_ROLLBACK_VERIFIED"
        finally:
            for child in children:
                child.stop()
            if not all(child.stopped for child in children):
                raise ServiceCycleError("OWNED_CHILD_CLEANUP_FAILED")
        # No existing process, backup, registry, port 8787, or live code was accessed.
        return {
            "result": outcome,
            "scenario": scenario,
            "old_process_verified": True,
            "target_process_verified": target_verified,
            "old_process_recovered": old_recovered,
            "replay_verified": replay_verified,
            "all_owned_processes_terminated": True,
            "only_disposable_service_instances": True,
            "simulated_worker_identity_only": True,
            "live_supervisor_restarted": False,
            "service_rollback_verified": False,
            "recovery_allowed": False,
            "production_touched": False,
            "secrets_read": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", choices=[CONFIRM], required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    args = parser.parse_args(argv)
    result: dict[str, Any] = {
        "schema_version": 1,
        "result": "ISOLATED_PROCESS_CYCLE_BLOCKED",
        "host": transaction.HOST,
        "repository": REPO,
        "source_sha": os.getenv("GITHUB_SHA", ""),
        "scenario": args.scenario,
        "service_rollback_verified": False,
        "recovery_allowed": False,
        "live_supervisor_restarted": False,
        "production_touched": False,
        "secrets_read": False,
    }
    try:
        if (os.name != "nt"
            or socket.gethostname().casefold() != transaction.HOST.casefold()
            or os.getenv("RUNNER_NAME") != RUNNER
            or os.getenv("GITHUB_REPOSITORY") != REPO
            or os.getenv("GITHUB_ACTIONS") != "true"
            or not re.fullmatch(r"[0-9a-f]{40}", result["source_sha"])):
            raise ServiceCycleError("HOST_OR_EXECUTOR_INVALID")
        status = rehearse(
            args.scenario,
            correlation_id=f"isolated-cycle-{os.getenv('GITHUB_RUN_ID', '')}-{os.getenv('GITHUB_RUN_ATTEMPT', '')}",
        )
        result.update(status)
        exit_code = 0
    except (ServiceCycleError, OSError, ValueError) as exc:
        result["blocker_code"] = str(exc) if isinstance(exc, ServiceCycleError) else "CYCLE_TEST_FAILED"
        exit_code = 2
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
