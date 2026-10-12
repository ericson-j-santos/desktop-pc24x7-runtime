"""Isolated shadow-server positive, negative and lifecycle tests.

Tests use a synthetic HTTP fixture; the physical Desktop E2E loads the actual
Orchestrator code and restored SQLite snapshot.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import desktop_orchestrator_shadow_service as shadow


FIXTURE_SERVER = '''from __future__ import annotations
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
parser=argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--host")
parser.add_argument("--port",type=int)
parser.add_argument("--db-path")
args=parser.parse_args()
assert args.command=="serve" and args.host=="127.0.0.1"
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): return
    def do_GET(self):
        payload = {"ready": True} if self.path=="/readyz" else {"ok":True} if self.path=="/healthz" else {}
        data=json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
HTTPServer(("127.0.0.1",args.port),Handler).serve_forever()
'''


class ShadowLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stage = Path(self.tmp.name) / "stage"
        (self.stage / "orchestrator").mkdir(parents=True)
        (self.stage / "data").mkdir()
        (self.stage / "orchestrator/__init__.py").write_text("")
        (self.stage / "orchestrator/__main__.py").write_text(FIXTURE_SERVER)
        db = self.stage / "data/orchestrator.db"
        with closing(sqlite3.connect(db)) as conn:
            with conn:
                conn.execute("CREATE TABLE test(id INTEGER PRIMARY KEY)")
                conn.execute("INSERT INTO test(id) VALUES(1)")

    def test_real_child_process_starts_and_exits_on_127_loopback(self):
        result = shadow.start_shadow(
            stage=self.stage, python_executable=sys.executable,
            port=shadow._port(), timeout_seconds=4,
        )
        self.assertTrue(result["shadow_ready"])
        self.assertTrue(result["shadow_health"])
        self.assertTrue(result["shadow_process_terminated"])
        self.assertEqual(result["shadow_bind"], "127.0.0.1")
        self.assertFalse(result["worker_started"])
        self.assertFalse(result["live_service_restarted"])
        self.assertFalse(result["recovery_allowed"])

    def test_child_exits_immediately_and_probe_fails_closed(self):
        (self.stage / "orchestrator/__main__.py").write_text("raise SystemExit(3)\n")
        with self.assertRaisesRegex(shadow.StateError, "SHADOW_EXITED_EARLY"):
            shadow.start_shadow(stage=self.stage, python_executable=sys.executable,
                                port=shadow._port(), timeout_seconds=5)

    def test_readiness_not_proven_times_out_without_leaving_child(self):
        with self.assertRaisesRegex(shadow.StateError, "SHADOW_READINESS_TIMEOUT"):
            shadow.start_shadow(
                stage=self.stage, python_executable=sys.executable,
                port=shadow._port(), timeout_seconds=0.5,
                request_fn=lambda _port, _path: None,
            )

    def test_invalid_port_and_missing_db_block_before_spawn(self):
        with patch.object(shadow.subprocess, "Popen", side_effect=AssertionError("must not start")):
            with self.assertRaisesRegex(shadow.StateError, "SHADOW_ARGUMENT_INVALID"):
                shadow.start_shadow(stage=self.stage,python_executable=sys.executable,port=0)
            (self.stage / "data/orchestrator.db").unlink()
            with self.assertRaises(ValueError):
                shadow.start_shadow(stage=self.stage,python_executable=sys.executable,port=12345)

    def test_request_filter_rejects_arbitrary_http_path(self):
        with self.assertRaisesRegex(shadow.StateError,"SHADOW_PATH_NOT_ALLOWLISTED"):
            shadow._request(9999,"/v1/status")

    def test_child_environment_excludes_credentials(self):
        with patch.dict(shadow.os.environ, {"GITHUB_TOKEN": "never-expose",
                                            "AWS_SECRET_ACCESS_KEY": "never-expose",
                                            "PATH": "example"}, clear=True):
            sanitized = shadow._safe_child_env()
        self.assertEqual(sanitized, {"PATH": "example"})
        self.assertNotIn("never-expose",json.dumps(sanitized))


if __name__ == "__main__":
    unittest.main()
