"""Real Windows E2E: native SQLite handle release with pinned Worker Pool."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory

PHASE = "entry"


def run():
    global PHASE
    PHASE = "host"
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("windows_runner_required")
    PHASE = "checkout"
    base = Path(__file__).resolve().parents[1]
    worker = base / "external" / "engineering-worker-pool"
    if not (worker / "app" / "store.py").is_file():
        raise RuntimeError("worker_source_missing")
    sys.path.insert(0, str(base))
    sys.path.insert(1, str(worker))
    from scripts.issue8_qwen7b_fenced_bundle_stage import closing_worker_pool_type
    from app.store import WorkerPoolStore
    PHASE = "pool_init"
    with TemporaryDirectory(prefix="issue8-workerpool-sqlite-") as d:
        path = Path(d) / "worker.db"
        pool = closing_worker_pool_type(WorkerPoolStore)(
            path, expected_rules_sha="4e6091a133f8d7d157abe6f83c31ca597812e0a4"
        )
        PHASE = "read_context"
        for _ in range(2):
            current = pool.fenced_cutover_status()
            if current["enabled"] is not False:
                raise RuntimeError("unexpected_pool_state")
            with pool._db() as conn:
                if conn.execute("SELECT 1").fetchone() != (1,):
                    raise RuntimeError("read_failure")
            try:
                conn.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                pass
            else:
                raise RuntimeError("connection_open_after_exit")
        PHASE = "unlink_sqlite"
        path.unlink()
        if path.exists():
            raise RuntimeError("database_not_released")
    PHASE = "complete"
    return {"result":"ISSUE8_SQLITE_CLOSE_REAL_WINDOWS_VERIFIED",
            "worker_sha":"21fd68dec6f0da92b3e7da201463401ac5429d64",
            "closed_and_removed":True, "replays":2,
            "no_model_inference":True, "no_remote_writes":True}


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as exc:
        kind = type(exc).__name__
        if kind not in {"RuntimeError","PermissionError","FileNotFoundError",
                        "OSError","ProgrammingError","OperationalError",
                        "AttributeError","TypeError","KeyError","ImportError"}:
            kind = "other"
        print(json.dumps({"result":"ISSUE8_SQLITE_CLOSE_REAL_WINDOWS_BLOCKED",
                          "reason_code":"smoke_failed",
                          "failure_phase":PHASE,
                          "exception_kind":kind}))
        raise SystemExit(2)
