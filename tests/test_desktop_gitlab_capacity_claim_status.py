"""Positive, negative, replay and structural controls for read-only Desktop claim status."""
import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import desktop_gitlab_capacity_claim_status as m


@contextlib.contextmanager
def guarded(root):
    # Portable fixture; native Windows ACL enforcement tested by Windows CI.
    m.claim.ordinary(root, True)
    yield lambda _fd: None


class ClaimStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / f"desktop-capacity-{m.ORIGINAL_REQUEST_ID}.claim.json"
        self.data = dict(
            request_id=m.ORIGINAL_REQUEST_ID, source_sha=m.ORIGINAL_SOURCE_SHA,
            rules_sha=m.ORIGINAL_RULES_SHA, issue_id="999999",
            issue_number=m.ORIGINAL_ISSUE_NUMBER, run_id="41718818357",
            run_attempt="1", host=m.HOST, schema=1, state="CLAIMED_UNCERTAIN",
            audit_state_changed=True, configuration_changed=False,
        )

    def tearDown(self):
        self.temp.cleanup()

    def read(self):
        return m.inspect(self.root, guard=guarded,
                         hostname=lambda: m.HOST, system=lambda: "Windows")

    def write(self, obj=None):
        raw = json.dumps(self.data if obj is None else obj, sort_keys=True).encode("ascii")
        self.target.write_bytes(raw)
        return raw

    def test_absence_cannot_authorize_replay(self):
        for _ in range(2):
            receipt = self.read()
            self.assertEqual(receipt["status"], "CLAIM_ABSENT_AT_READ_TIME")
            self.assertFalse(receipt["replay_authorized"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_present_uncertain_is_repeatable_and_does_not_mutate(self):
        before = self.write()
        first, second = self.read(), self.read()
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "CLAIM_PRESENT_UNCERTAIN")
        self.assertTrue(first["claim_present"])
        self.assertFalse(first["replay_authorized"])
        self.assertFalse(first["configuration_changed"])
        self.assertFalse(first["secrets_accessed"])
        self.assertEqual(before, self.target.read_bytes())

    def test_invalid_identifiers_state_and_extra_fields_block(self):
        for changes in (
            {"source_sha": "a" * 40}, {"rules_sha": "b" * 40},
            {"request_id": "00000000-0000-4000-8000-000000000000"},
            {"issue_number": "129"}, {"run_attempt": "2"},
            {"host": "other"}, {"state": "CLAIMED"},
            {"audit_state_changed": False}, {"configuration_changed": True},
            {"schema": 2}, {"secret": "PRIVATE_SENTINEL"},
        ):
            with self.subTest(changes=changes):
                raw = self.write({**self.data, **changes})
                with self.assertRaises(m.ReadbackRejected):
                    self.read()
                self.assertEqual(raw, self.target.read_bytes())

    def test_broken_and_oversized_claims_fail_closed(self):
        for raw in (b"", b"{broken", b"X" * 4097, b'"string"'):
            with self.subTest(size=len(raw)):
                self.target.write_bytes(raw)
                with self.assertRaises(m.ReadbackRejected):
                    self.read()
                self.assertEqual(raw, self.target.read_bytes())

    def test_symlink_is_not_followed(self):
        outside = self.root / "outside"
        outside.write_text("KEEP")
        try:
            self.target.symlink_to(outside)
        except OSError:
            self.skipTest("symlink privilege not enabled")
        with self.assertRaises(m.claim.ClaimError):
            self.read()
        self.assertEqual(outside.read_text(), "KEEP")

    def test_host_os_and_missing_root_are_fail_closed(self):
        for host, system in (("UNTRUSTED", "Windows"), (m.HOST, "Linux")):
            with self.subTest(host=host, system=system), self.assertRaises(m.ReadbackRejected):
                m.inspect(self.root, guard=guarded, hostname=lambda: host,
                          system=lambda: system)
        with self.assertRaises(FileNotFoundError):
            m.inspect(self.root / "missing", guard=guarded,
                      hostname=lambda: m.HOST, system=lambda: "Windows")

    def test_denied_acl_is_not_treated_as_absence(self):
        @contextlib.contextmanager
        def denied(_root):
            raise m.claim.ClaimError("DACL_OTHER_PRINCIPAL_REJECTED")
            yield None
        with self.assertRaises(m.claim.ClaimError):
            m.inspect(self.root, guard=denied, hostname=lambda: m.HOST,
                      system=lambda: "Windows")

    def test_main_redacts_failure(self):
        with patch.object(m, "inspect", side_effect=RuntimeError("PRIVATE_SENTINEL")):
            with patch.dict(os.environ, {"LOCALAPPDATA": str(self.root)}):
                import io
                from contextlib import redirect_stdout
                output = io.StringIO()
                with redirect_stdout(output):
                    result = m.main()
                self.assertEqual(result, 2)
                self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
                self.assertEqual(json.loads(output.getvalue())["status"],
                                 "CLAIM_READBACK_BLOCKED")

    def test_fixed_host_and_request_no_arbitrary_cli(self):
        source = (ROOT / "scripts/desktop_gitlab_capacity_claim_status.py").read_text()
        for prohibited in ("subprocess", "argparse", "eval(", "os.system"):
            self.assertNotIn(prohibited, source)
        self.assertIn("windows_private_root", source)
        self.assertIn("verify_file(stream.fileno())", source)

    def test_workflow_keeps_manual_claim_check_risk1_only(self):
        workflow = (ROOT / ".github/workflows/desktop-gitlab-capacity-readonly.yml").read_text()
        start = workflow.index("      - name: Inspect original capacity claim without consuming")
        stop = workflow.index("      - name: Consume issue request", start)
        probe = workflow[start:stop]
        self.assertIn("github.event_name == 'workflow_dispatch'", probe)
        self.assertIn("--risk 1", probe)
        self.assertNotIn("--risk 2", probe)
        self.assertIn("scripts/desktop_gitlab_capacity_claim_status.py", probe)
        self.assertIn("CLAIM_READBACK_BLOCKED", probe)
        self.assertIn("CLAIM_PRESENT_UNCERTAIN", probe)
        self.assertIn("CLAIM_ABSENT_AT_READ_TIME", probe)
        self.assertIn("configuration_changed -ne $false", probe)
        self.assertIn("replay_authorized -ne $false", probe)
        self.assertNotIn("Write-Output $raw", probe)
        self.assertNotIn("Write-Output $receipt", probe)
        self.assertLess(workflow.index("      - name: Materialize current SHA"),
                        workflow.index("      - name: Inspect original capacity claim"))
        self.assertNotIn("  schedule:", workflow)
        self.assertNotIn("  push:", workflow)


if __name__ == "__main__":
    unittest.main()
