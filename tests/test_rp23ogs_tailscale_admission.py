import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import rp23ogs_tailscale_admission as g

ID = "pass001-rp23ogs-test-20261121"
KEY = "cofre-senhas-api:PASS-001:rp23ogs-msi-1.104.7"


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.req = g.fixed_request(ID, KEY)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "tailscale-pass001-staging"
        self.root.mkdir()
        self.good = dict(request=self.req, stage_root=self.root, official_digest_bytes=None,
                         signature_attestation=None, actual_host=g.HOST, system="Windows", machine="AMD64")

    def test_real_cli_does_not_install(self):
        # On non-Windows host must block before source/installation.
        self.assertEqual(g.main(), 20)

    def test_without_official_checksum_blocked(self):
        with self.assertRaisesRegex(g.AdmissionBlocked, "OFFICIAL_SHA256_ATTESTATION_REQUIRED"):
            g.qualify(**self.good)

    def test_other_pc_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked, "PHYSICAL_HOST_MISMATCH"):
            g.qualify(**(self.good | {"actual_host": "Noteri"}))

    def test_non_windows_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked, "PHYSICAL_HOST_MISMATCH"):
            g.qualify(**(self.good | {"system": "Linux"}))

    def test_windows_arm_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked, "PHYSICAL_HOST_MISMATCH"):
            g.qualify(**(self.good | {"machine": "ARM64"}))

    def test_other_environment_denied(self):
        r = g.Request(g.CONTRACT,g.HOST,"PROD",g.VERSION,g.RULES_SHA,ID,KEY)
        with self.assertRaisesRegex(g.AdmissionBlocked,"REQUEST_SCOPE_MISMATCH"):
            g.qualify(**(self.good | {"request": r}))

    def test_sha_not_pinned_denied(self):
        r = g.Request(g.CONTRACT,g.HOST,g.ENV,g.VERSION,"0"*40,ID,KEY)
        with self.assertRaisesRegex(g.AdmissionBlocked,"REQUEST_SCOPE_MISMATCH"):
            g.qualify(**(self.good | {"request": r}))

    def test_invalid_correlation_denied(self):
        r = g.Request(g.CONTRACT,g.HOST,g.ENV,g.VERSION,g.RULES_SHA,"x",KEY)
        with self.assertRaisesRegex(g.AdmissionBlocked,"REQUEST_ID_INVALID"):
            g.qualify(**(self.good | {"request": r}))

    def test_digest_mismatch_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"DIGEST_SOURCES_DISAGREE"):
            g.qualify(**(self.good | {"official_digest_bytes": ("0"*64).encode()}))

    def test_wrong_filename_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"OFFICIAL_DIGEST_WRONG_FILE"):
            g.parse_official_digest((g.SECONDARY_SHA256+" bad.msi").encode())

    def test_duplicate_hash_records_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"OFFICIAL_DIGEST_INVALID"):
            g.parse_official_digest((g.SECONDARY_SHA256+"\n"+g.SECONDARY_SHA256).encode())

    def test_oversized_checksum_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"OFFICIAL_DIGEST_INVALID"):
            g.parse_official_digest(b"a"*301)

    def test_package_must_be_staged(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"PACKAGE_NOT_STAGED"):
            g.qualify(**(self.good | {"official_digest_bytes": g.SECONDARY_SHA256.encode()}))

    def test_small_fake_msi_denied(self):
        (self.root/g.MSI_NAME).write_bytes(b"garbage")
        with self.assertRaisesRegex(g.AdmissionBlocked,"PACKAGE_SIZE_INVALID"):
            g.qualify(**(self.good | {"official_digest_bytes": g.SECONDARY_SHA256.encode()}))

    def test_stage_path_denied(self):
        with self.assertRaisesRegex(g.AdmissionBlocked,"STAGE_ROOT_DENIED"):
            g.qualify(**(self.good | {"stage_root": Path(self.tmp.name)}))

    def test_unsigned_msi_denied_with_mocked_read(self):
        with patch.object(g,"read_staged_msi",return_value=g.SECONDARY_SHA256):
            with self.assertRaisesRegex(g.AdmissionBlocked,"WINDOWS_SIGNATURE_NOT_ATTESTED"):
                g.qualify(**(self.good | {"official_digest_bytes": g.SECONDARY_SHA256.encode()}))

    def test_signed_msi_precheck_still_blocks_install(self):
        with patch.object(g,"read_staged_msi",return_value=g.SECONDARY_SHA256):
            result = g.qualify(**(self.good | {"official_digest_bytes": g.SECONDARY_SHA256.encode(),
                                              "signature_attestation": lambda path: True}))
        self.assertEqual(result["result"],"PACKAGE_PRECHECK_PASSED_INSTALL_STILL_BLOCKED")
        self.assertFalse(result["installation_executed"])
        self.assertFalse(result["installation_authorized_by_gate"])
        self.assertFalse(result["privilege_elevation_authorized"])
        self.assertFalse(result["rollback_tested"])

    def test_fixed_url_is_official(self):
        self.assertEqual(g.OFFICIAL_ORIGIN,"https://pkgs.tailscale.com/stable/tailscale-setup-1.104.7-amd64.msi")


if __name__ == "__main__":
    unittest.main()
