"""Positive, negative and privacy checks; no host touched by these tests."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / "scripts" / "reqsys_dev_locator_risk1_inventory.py"
SPEC = importlib.util.spec_from_file_location("reqsys_locator_risk1_test", FILE)
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)
SRC = "a" * 40
REQ = "b" * 40
PUB = b"# publisher source\n"
PUBSHA = hashlib.sha256(PUB).hexdigest()
CID = "reqsys1596-locator-20261120"
TASK_XML = b'''<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><CalendarTrigger><Repetition><Interval>PT6M</Interval></Repetition></CalendarTrigger></Triggers>
<Principals><Principal><LogonType>InteractiveToken</LogonType></Principal></Principals>
<Settings><Enabled>true</Enabled></Settings></Task>'''


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "ReqSys"
        self.root.mkdir()
        self.make("RuntimeSupervisor/manifest.json", {"schema_version": "2.0.0", "source_head": REQ,
                                                       "source_root": "SECRET_RUNTIME_DIR"})
        self.make("RuntimeSupervisor/dev-locator-public.json", {"topic": m.TOPIC,
                                                                 "public_key_b64": m.PUBLIC_KEY})
        self.make("PublicRuntime/dev-tunnels.json", {"tunnels": [
            {"url": "https://valid-example.trycloudflare.com", "ready": True,
             "secret_value": "NEVER_LEAK"}]})
        self.make("PublicRuntime/dev-locator-publish.json", {"published": True,
            "healthy_url_count": 1, "expires_at": 2000, "topic": m.TOPIC,
            "public_key_b64": m.PUBLIC_KEY, "selected_url": "https://valid-example.trycloudflare.com"})
        self.make("PublicRuntime/dev-supervisor.json", {"schema_version": "2.0.0",
            "ready": True, "local_runtime_contract_ready": True, "locator_ready": True,
            "timestamp_epoch": 1200, "password": "VERY_SECRET"})
        self.raw(m.ROOT_PUBLISHER.as_posix(), PUB)
        self.raw(m.ROOT_SUPERVISOR.as_posix(), b"# supervisor\n")
        self.calls = []

    def raw(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def make(self, name, data):
        self.raw(name, json.dumps(data).encode())

    def http(self, path):
        self.calls.append(path)
        if path == "/@vite/client":
            return 404, b""
        if path == "/api/runtime/build-info":
            return 200, json.dumps({"data": {"build_sha": REQ, "token": "NOT_ALLOWED"}}).encode()
        return 200, b"{}"

    def observe(self, **options):
        settings = dict(root=self.root, now=1300, source_sha=SRC,
                        expected_reqsys_sha=REQ, expected_publisher_sha256=PUBSHA,
                        correlation_id=CID, task_reader=lambda: TASK_XML, request=self.http)
        settings.update(options)
        return m.collect(**settings)

    def test_positive_hashes_and_privacy_without_promoting_dev(self):
        result = self.observe()
        self.assertEqual(result["result"], "LOCATOR_RISK1_INVENTORY_OBSERVED")
        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["files"]["publisher_script"]["matches_reqsys_source"])
        self.assertTrue(result["scheduled_publisher"]["interval_is_six_minutes"])
        self.assertFalse(result["ready_for_dev"])
        self.assertFalse(result["locator_signature_independently_verified"])
        self.assertFalse(result["publisher_process_identity_verified"])
        raw = json.dumps(result)
        for secret in ("SECRET_RUNTIME_DIR", "NEVER_LEAK", "VERY_SECRET",
                       "valid-example", "selected_url", "password"):
            self.assertNotIn(secret, raw)
        self.assertEqual(self.calls, list(m.ENDPOINTS))

    def test_replay_idempotent_and_does_not_modify_source_files(self):
        before = {p: (self.root / p).read_bytes() for p in m.FILES.values()}
        self.assertEqual(self.observe(), self.observe())
        self.assertEqual(before, {p: (self.root / p).read_bytes() for p in m.FILES.values()})

    def test_empty_tunnel_and_expired_publication_are_not_approved(self):
        self.make("PublicRuntime/dev-tunnels.json", {"tunnels": [], "token": "secret"})
        self.make("PublicRuntime/dev-locator-publish.json", {"published": True,
              "expires_at": 100, "healthy_url_count": 0})
        x = self.observe()
        self.assertIn("ingress_url_absent_or_invalid", x["blockers"])
        self.assertIn("publication_unverified_or_expired", x["blockers"])

    def test_old_publisher_sha_blocks_and_do_not_guess_emitter(self):
        x = self.observe(expected_publisher_sha256="0"*64)
        self.assertIn("installed_publisher_not_current", x["blockers"])
        self.assertFalse(x["publisher_process_identity_verified"])

    def test_task_not_registered_blocks(self):
        x = self.observe(task_reader=lambda: None)
        self.assertEqual(x["scheduled_publisher"]["query_status"], "unavailable_or_not_registered")
        self.assertIn("publisher_schedule_not_enabled", x["blockers"])

    def test_local_non_200_and_wrong_build_sha_block(self):
        x = self.observe(request=lambda path: (200, b'{"build_sha":"' + SRC.encode() + b'"}')
                         if path == "/api/runtime/build-info" else (503,b""))
        self.assertIn("local_runtime_contract_unavailable", x["blockers"])
        self.assertIn("reqsys_dev_build_sha_unverified", x["blockers"])
        self.assertIn("static_frontend_negative_unverified", x["blockers"])

    def test_malformed_json_and_duplicate_keys_fail_closed(self):
        self.raw("PublicRuntime/dev-tunnels.json", b'{"tunnels":[],"tunnels":[]}')
        with self.assertRaisesRegex(m.InventoryBlocked, "fixed_json_invalid"):
            self.observe()
        self.raw("PublicRuntime/dev-tunnels.json", b'not-json')
        with self.assertRaisesRegex(m.InventoryBlocked, "fixed_json_invalid"):
            self.observe()

    def test_symlink_rejected_without_reading_target(self):
        file = self.root / "PublicRuntime/dev-tunnels.json"
        file.unlink()
        try:
            file.symlink_to(self.root / "RuntimeSupervisor/manifest.json")
        except OSError:
            self.skipTest("Symlink creation not permitted")
        with self.assertRaisesRegex(m.InventoryBlocked, "fixed_path_redirected"):
            self.observe()

    def test_hardlink_rejected(self):
        file = self.root / "PublicRuntime/dev-tunnels.json"
        other = self.root / "other-hardlink"
        try:
            other.hardlink_to(file)
        except OSError:
            self.skipTest("Hardlinks not permitted")
        with self.assertRaisesRegex(m.InventoryBlocked, "fixed_file_invalid"):
            self.observe()

    def test_untrusted_url_rejected_without_emission(self):
        for url in ("https://user:pass@valid.trycloudflare.com",
                    "https://valid.trycloudflare.com/steal?x=1",
                    "http://valid.trycloudflare.com", "https://evil.example"):
            with self.subTest(url=url):
                self.make("PublicRuntime/dev-tunnels.json", {"tunnels": [{"url": url}]})
                report = self.observe()
                self.assertIn("ingress_url_absent_or_invalid", report["blockers"])
                self.assertNotIn(url, json.dumps(report))

    def test_invalid_host_sha_and_raw_command_rejected(self):
        for change in ({"source_sha": "main"}, {"correlation_id": "x"},
                       {"expected_publisher_sha256": "xxx"}):
            with self.subTest(change=change), self.assertRaises(m.InventoryBlocked):
                self.observe(**change)
        with self.assertRaisesRegex(m.InventoryBlocked,"local_path_unapproved"):
            m.local_request("http://external.invalid/")

    def test_task_xml_does_not_export_command_arguments(self):
        raw = TASK_XML.replace(b"</Task>", b"<Actions><Exec><Command>SENSITIVE_PATH</Command></Exec></Actions></Task>")
        self.assertNotIn("SENSITIVE_PATH", json.dumps(m.task_summary(raw)))
        self.assertTrue(m.task_summary(raw)["task_enabled"])

    def test_env_rejects_non_authorized_host_before_schtasks_and_http(self):
        env = dict(GITHUB_SHA=SRC, GITHUB_REPOSITORY=m.REPO,
                   COMPUTERNAME="NOTERI", RUNNER_NAME=m.RUNNER,
                   LOCALAPPDATA=str(self.root.parent))
        with patch.dict(m.os.environ, env, clear=True):
            with patch.object(m, "task_xml_reader") as task:
                with self.assertRaisesRegex(m.InventoryBlocked, "physical_source_identity_unverified"):
                    m.main(["--expected-head",SRC,"--expected-reqsys-sha",REQ,
                            "--expected-publisher-sha256",PUBSHA,"--correlation-id",CID])
                task.assert_not_called()


if __name__ == "__main__":
    unittest.main()
