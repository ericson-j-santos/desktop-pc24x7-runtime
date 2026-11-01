"""Real filesystem race/replay tests, plus Windows guard fails closed off-host."""
import concurrent.futures
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("claim", Path(__file__).resolve().parents[1] / "scripts/desktop_gitlab_capacity_claim.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
META = {"request_id": "01234567-89ab-4def-8123-456789abcdef", "source_sha": "a" * 40, "rules_sha": "b" * 40, "issue_id": "100", "issue_number": "12", "run_id": "123456789", "run_attempt": "1", "host": m.HOST}

@contextlib.contextmanager
def local_test_guard(root):
    # Test-only filesystem, not a claim about Windows ACL validation.
    m.ordinary(root, True)
    yield lambda fd: None

class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, data=None):
        return m.claim(self.root, META if data is None else data, local_test_guard)

    def target(self):
        return self.root / ("desktop-capacity-" + META["request_id"] + ".claim.json")

    def test_success_readback_and_replay_different_run_sha_issue(self):
        result = self.call()
        self.assertTrue(result["audit_state_changed"])
        self.assertFalse(result["configuration_changed"])
        self.assertEqual(json.loads(self.target().read_text())["state"], "CLAIMED_UNCERTAIN")
        original = self.target().read_bytes()
        for changes in ({}, {"run_id": "999"}, {"source_sha": "c" * 40}, {"issue_id": "999"}):
            with self.subTest(changes=changes), self.assertRaises(m.ClaimError):
                self.call({**META, **changes})
        self.assertEqual(original, self.target().read_bytes())

    def test_real_concurrent_create_exactly_one_winner(self):
        def attempt(_):
            try:
                return self.call()["claimed"]
            except m.ClaimError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(attempt, range(32)))
        self.assertEqual(sum(outcomes), 1)

    def test_partial_corrupt_claims_always_block(self):
        for raw in (b"", b"{broken", b'{"state":"CLAIMED_UNCERTAIN"}'):
            with self.subTest(raw=raw):
                self.target().write_bytes(raw)
                with self.assertRaises(m.ClaimError):
                    self.call()
                self.assertEqual(self.target().read_bytes(), raw)

    def test_failed_flush_leaves_consumed_claim(self):
        with patch.object(m.os, "fsync", side_effect=OSError("injected failure")):
            with self.assertRaises(OSError):
                self.call()
        self.assertTrue(self.target().exists())
        with self.assertRaises(m.ClaimError):
            self.call()

    def test_crash_after_claim_does_not_enable_retry(self):
        self.call()
        # No collection performed; next process/attempt still must not reclaim.
        with self.assertRaises(m.ClaimError):
            self.call()

    def test_invalid_metadata_does_not_create_claim(self):
        for changes in ({"run_attempt": "2"}, {"host": "OTHER"}, {"request_id": "../x"}, {"source_sha": "abc"}, {"issue_id": True}, {"extra": "x"}):
            with self.subTest(changes=changes), self.assertRaises(m.ClaimError):
                self.call({**META, **changes})
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_symlink_is_never_followed(self):
        outside = self.root / "outside"
        outside.write_bytes(b"unchanged")
        self.target().symlink_to(outside)
        with self.assertRaises(m.ClaimError):
            self.call()
        self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_root_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.ClaimError):
            m.claim(alias, META, local_test_guard)

    def test_missing_root_is_not_created(self):
        missing = self.root / "missing"
        with self.assertRaises(FileNotFoundError):
            m.claim(missing, META, local_test_guard)
        self.assertFalse(missing.exists())

    def test_guard_failure_prevents_creation(self):
        @contextlib.contextmanager
        def denied(root):
            raise m.ClaimError("DACL_OTHER_PRINCIPAL_REJECTED")
            yield root
        with self.assertRaises(m.ClaimError):
            m.claim(self.root, META, denied)
        self.assertEqual(list(self.root.iterdir()), [])


    def test_replaced_file_with_identical_bytes_fails_readback(self):
        original_ordinary = m.ordinary
        replaced = []
        def replace_after_close(path, directory):
            if path == self.target() and not directory and not replaced:
                payload = path.read_bytes()
                original_inode = path.stat().st_ino
                path.rename(self.root / "preserved-original")
                path.write_bytes(payload)
                replaced.append(path.stat().st_ino != original_inode)
            return original_ordinary(path, directory)
        with patch.object(m, "ordinary", side_effect=replace_after_close):
            with self.assertRaisesRegex(m.ClaimError, "CLAIM_READBACK_FAILED"):
                self.call()
        self.assertEqual(replaced, [True])
        with self.assertRaises(m.ClaimError):
            self.call()

    def test_native_windows_guard_not_replaced_by_posix_mode(self):
        with patch.object(m.os, "name", "posix"):
            with self.assertRaises(m.ClaimError):
                m.claim(self.root, META)

if __name__ == "__main__":
    unittest.main()
