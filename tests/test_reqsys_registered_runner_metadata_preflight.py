"""Contract tests for the fixed ReqSys runner metadata probe."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("runner_probe", Path(__file__).resolve().parents[1] / "scripts" / "reqsys_registered_runner_metadata_preflight.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "bin").mkdir()
        (self.root / "run.cmd").write_text("", encoding="utf-8")
        (self.root / "bin" / "Runner.Listener.exe").write_bytes(b"public-test-fixture")
        self.write({"gitHubUrl": probe.EXPECTED_REPOSITORY_URL, "agentName": "DESKTOP-PDQK954"})
        # Must never be opened, even when registration metadata is accepted.
        (self.root / ".credentials").write_text("SENTINEL_PRIVATE_DO_NOT_READ", encoding="utf-8")

    def write(self, value):
        (self.root / ".runner").write_text(json.dumps(value), encoding="utf-8")

    def test_accepts_exact_repo_and_outputs_only_public_fields(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path.name == ".credentials":
                raise AssertionError("private credential file opened")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", guarded):
            facts = probe.metadata_facts(self.root)
        self.assertEqual(facts["runner_name"], "DESKTOP-PDQK954")
        self.assertTrue(facts["repository_matches_reqsys"])
        self.assertNotIn("SENTINEL", json.dumps(facts))

    def test_other_repo_and_conflicting_url_fail_closed(self):
        for data in (
            {"gitHubUrl": "https://github.com/ericson-j-santos/desktop-pc24x7-runtime", "agentName": "Desktop"},
            {"gitHubUrl": probe.EXPECTED_REPOSITORY_URL, "repoUrl": "https://github.com/other/repo", "agentName": "Desktop"},
            {"gitHubUrl": probe.EXPECTED_REPOSITORY_URL + "?token=private", "agentName": "Desktop"},
        ):
            with self.subTest(data=data):
                self.write(data)
                with self.assertRaisesRegex(probe.ProbeError, "REPOSITORY_MISMATCH"):
                    probe.metadata_facts(self.root)

    def test_missing_registration_and_executable_fail_closed(self):
        (self.root / ".runner").unlink()
        with self.assertRaises(probe.ProbeError):
            probe.metadata_facts(self.root)
        self.write({"repoUrl": probe.EXPECTED_REPOSITORY_URL, "agentName": "Desktop"})
        (self.root / "bin" / "Runner.Listener.exe").unlink()
        with self.assertRaises(probe.ProbeError):
            probe.metadata_facts(self.root)

    def test_invalid_and_oversized_registration_fail_closed(self):
        (self.root / ".runner").write_bytes(b"{invalid")
        with self.assertRaisesRegex(probe.ProbeError, "METADATA_INVALID"):
            probe.metadata_facts(self.root)
        (self.root / ".runner").write_bytes(b"x" * (probe.MAX_METADATA_BYTES + 1))
        with self.assertRaisesRegex(probe.ProbeError, "TOO_LARGE"):
            probe.metadata_facts(self.root)

    def test_redirected_registration_is_rejected(self):
        target = self.root / "public-other.json"
        target.write_text("{}", encoding="utf-8")
        (self.root / ".runner").unlink()
        try:
            (self.root / ".runner").symlink_to(target)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(probe.ProbeError, "REPARSE_REJECTED"):
            probe.metadata_facts(self.root)

if __name__ == "__main__":
    unittest.main()
