"""Positive, negative and repeat read-only supervisor preflight checks."""
import errno
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import orchestrator_supervisor_readonly_probe as probe

SHA = "a" * 40

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = time.time()
        (self.root / "data" / "control").mkdir(parents=True)
        self.version = self.root / "runtime-version.json"
        self.status = self.root / "runtime-status.json"
        self.version.write_text(json.dumps({"schema_version": 1, "source_sha": SHA}))
        self.status.write_text(json.dumps({"updated_at_epoch": self.now, "ready": True, "supervisor_pid": 55}))

    @staticmethod
    def worker():
        return {"runtime_source_sha": SHA, "fresh": True, "eligible": True,
                "online": True, "auth_valid": True}

    def collect(self, worker=None):
        return probe.collect(root=self.root, now=self.now, worker_fn=worker or self.worker)

    def test_positive_and_idempotent(self):
        first = self.collect()
        self.assertEqual(first, self.collect())
        self.assertTrue(first["live_state_consistent"])
        self.assertFalse(first["pending_refresh_present"])
        self.assertFalse(first["original_receipt_identity_verified"])

    def test_mismatched_worker_sha_rejected(self):
        self.assertFalse(self.collect(lambda: {**self.worker(), "runtime_source_sha": "b"*40})["live_state_consistent"])

    def test_stale_status_rejected(self):
        self.status.write_text(json.dumps({"updated_at_epoch": self.now-301, "ready": True, "supervisor_pid": 55}))
        self.assertFalse(self.collect()["live_state_consistent"])

    def test_pending_record_is_observation_not_permission(self):
        (self.root / "data" / "control" / "refresh-runtime.request.json").write_text("do-not-read-content")
        self.assertTrue(self.collect()["pending_refresh_present"])
        self.assertNotIn("do-not-read-content", str(self.collect()))

    def test_unrelated_failures_counted_not_exposed(self):
        (self.root / "data" / "control" / "refresh-runtime.failed.123.json").write_text("do-not-read-content")
        self.assertEqual(self.collect()["failure_receipt_count"], 1)

    def test_duplicate_json_key_rejected(self):
        self.version.write_text('{"source_sha":"'+SHA+'","source_sha":"'+SHA+'"}')
        with self.assertRaises(Exception):
            self.collect()

    def test_symlink_rejected(self):
        self.version.unlink()
        try:
            self.version.symlink_to(self.status)
        except OSError:
            self.skipTest("symlink requires privilege")
        with self.assertRaises(Exception):
            self.collect()

    def test_missing_version_fails_closed(self):
        self.version.unlink()
        with self.assertRaises(Exception):
            self.collect()

    def test_fixed_loopback_readiness_and_no_redirect(self):
        requested = []
        class Response:
            status = 200
            def read(self, limit):
                self.limit = limit
                return b'{"ready":true}'
        class Connection:
            def __init__(self, host, port, timeout):
                requested.append(("connect", host, port, timeout))
                self.closed = False
                self.response = Response()
            def request(self, method, path, headers):
                requested.append(("request", method, path, headers))
            def getresponse(self):
                return self.response
            def close(self):
                self.closed = True
                requested.append(("close",))
        result = probe.observe_local_readiness(connection_factory=Connection)
        self.assertEqual(result, {"healthy": True, "failure_class": "none", "http_status": 200})
        self.assertEqual(requested[0], ("connect", "127.0.0.1", 8787, 4))
        self.assertEqual(requested[1][1:3], ("GET", "/readyz"))
        self.assertEqual(requested[2], ("close",))

    def test_loopback_redirect_rejected_without_following(self):
        requested = []
        class Response:
            status = 302
        class Connection:
            def __init__(self, host, port, timeout):
                requested.append(("connect", host, port))
            def request(self, method, path, headers):
                requested.append(("request", method, path))
            def getresponse(self):
                return Response()
            def close(self):
                requested.append(("close",))
        result = probe.observe_local_readiness(connection_factory=Connection)
        self.assertEqual(result["failure_class"], "http_non_200")
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(sum(1 for item in requested if item[0] == "request"), 1)

    def test_loopback_transport_failures_are_sanitized(self):
        for error, category in (
            (ConnectionRefusedError(errno.ECONNREFUSED, "private-refused"), "connection_refused"),
            (TimeoutError(errno.ETIMEDOUT, "private-timeout"), "timeout"),
            (OSError(errno.ENETUNREACH, "private-net"), "network_unreachable"),
        ):
            with self.subTest(category=category):
                class Connection:
                    def __init__(self, host, port, timeout):
                        pass
                    def request(self, method, path, headers):
                        raise error
                    def close(self):
                        pass
                result = probe.observe_local_readiness(connection_factory=Connection)
                self.assertEqual(result, {"healthy": False, "failure_class": category})
                self.assertNotIn("private-", str(result))

    def test_loopback_unready_malformed_and_oversize_are_rejected(self):
        class Response:
            status = 200
            def __init__(self, payload):
                self.payload = payload
            def read(self, limit):
                self.limit = limit
                return self.payload
        for raw, category in (
            (b'{"ready":false}', "readiness_false"),
            (b'broken', "response_invalid"),
            (b'X'*8193, "response_too_large"),
        ):
            with self.subTest(category=category):
                class Connection:
                    def __init__(self, host, port, timeout):
                        pass
                    def request(self, method, path, headers):
                        pass
                    def getresponse(self):
                        return Response(raw)
                    def close(self):
                        pass
                result = probe.observe_local_readiness(connection_factory=Connection)
                self.assertEqual(result["failure_class"], category)
                self.assertEqual(result["http_status"], 200)

    def test_loopback_is_observed_before_installation_metadata(self):
        import inspect
        source = inspect.getsource(probe.main)
        self.assertLess(
            source.index('result["loopback_readiness"] = observe_local_readiness()'),
            source.index("facts = collect()"),
        )

if __name__ == "__main__":
    unittest.main()
