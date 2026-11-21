"""Negative/security controls for the RP23OGS read-only Windows MSI evidence adapter."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import rp23ogs_tailscale_admission as base
from scripts import rp23ogs_tailscale_windows_evidence as e


class _Response:
    def __init__(self, data: bytes, url: str = base.OFFICIAL_DIGEST_URL, status: int = 200):
        self.data = data
        self.url = url
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def read(self, size):
        return self.data[:size]


class _Opener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        return self.response


class SignatureAndChecksumTests(unittest.TestCase):
    def test_exact_official_origin_and_bounded_https(self):
        op = _Opener(_Response(base.SECONDARY_SHA256.encode()))
        self.assertEqual(e.get_official_digest(opener=op), base.SECONDARY_SHA256.encode())
        self.assertEqual(op.request.full_url, base.OFFICIAL_DIGEST_URL)
        self.assertTrue(op.request.full_url.startswith('https://pkgs.tailscale.com/stable/'))
        self.assertEqual(op.timeout, 12)

    def test_wrong_host_or_redirect_denied(self):
        op = _Opener(_Response(base.SECONDARY_SHA256.encode(), url='https://evil.example/sha256'))
        with self.assertRaisesRegex(e.EvidenceBlocked, 'OFFICIAL_DIGEST_ORIGIN_MISMATCH'):
            e.get_official_digest(opener=op)

    def test_non_200_denied(self):
        with self.assertRaisesRegex(e.EvidenceBlocked, 'OFFICIAL_DIGEST_ORIGIN_MISMATCH'):
            e.get_official_digest(opener=_Opener(_Response(b'', status=302)))

    def test_oversized_or_empty_digest_denied(self):
        for body in (b'', b'0' * 301):
            with self.subTest(size=len(body)), self.assertRaisesRegex(e.EvidenceBlocked, 'OFFICIAL_DIGEST_SIZE_INVALID'):
                e.get_official_digest(opener=_Opener(_Response(body)))

    def test_secondary_disagreement_denied(self):
        with self.assertRaisesRegex(e.EvidenceBlocked, 'DIGEST_SOURCES_DISAGREE'):
            e.get_official_digest(opener=_Opener(_Response(b'0' * 64)))

    def test_malformed_official_data_denied(self):
        with self.assertRaisesRegex(base.AdmissionBlocked, 'OFFICIAL_DIGEST_INVALID'):
            e.get_official_digest(opener=_Opener(_Response(b'not-a-digest')))

    def test_non_windows_rejects_signer_without_windows_call(self):
        with tempfile.TemporaryDirectory() as td, patch.object(e.platform, 'system', return_value='Linux'):
            with self.assertRaisesRegex(e.EvidenceBlocked, 'WINDOWS_SIGNATURE_HOST_REQUIRED'):
                e.verify_windows_authenticode(Path(td) / base.MSI_NAME)

    def test_unsigned_file_denied_on_windows(self):
        if os.name != 'nt':
            self.skipTest('Only Windows has native WinVerifyTrust')
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / base.MSI_NAME
            file.write_bytes(b'0' * 1024)
            with self.assertRaises(e.EvidenceBlocked):
                e.verify_windows_authenticode(file)


class RollbackAndFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'tailscale-pass001-staging'
        self.root.mkdir()
        self.file = self.root / base.MSI_NAME

    def test_does_not_claim_rollback_tested(self):
        with patch.object(base, 'read_staged_msi', return_value=base.SECONDARY_SHA256):
            p = e.rollback_plan(package=self.file, verified_digest=base.SECONDARY_SHA256)
        self.assertTrue(p['rollback_plan_checked'])
        self.assertTrue(p['rollback_source_readback'])
        self.assertFalse(p['rollback_tested'])
        self.assertFalse(p['installed_state_backup_verified'])
        self.assertFalse(p['install_authorized_by_gate'])

    def test_rollback_digest_mismatch_denied(self):
        with patch.object(base, 'read_staged_msi', return_value='0' * 64):
            with self.assertRaisesRegex(e.EvidenceBlocked, 'ROLLBACK_SOURCE_CHANGED'):
                e.rollback_plan(package=self.file, verified_digest=base.SECONDARY_SHA256)

    def test_rollback_other_package_denied(self):
        with self.assertRaisesRegex(e.EvidenceBlocked, 'ROLLBACK_SOURCE_MISMATCH'):
            e.rollback_plan(package=self.root / 'other.msi', verified_digest=base.SECONDARY_SHA256)

    def test_preflight_missing_package_fails_before_network_or_signature(self):
        with patch.object(e.socket, 'gethostname', return_value=base.HOST), \
             patch.object(e.platform, 'system', return_value='Windows'), \
             patch.object(e.platform, 'machine', return_value='AMD64'), \
             patch.object(e.Path, 'cwd', return_value=Path(self.tmp.name)), \
             patch.object(e, 'get_official_digest') as fetch, \
             patch.object(e, 'verify_windows_authenticode') as signed:
            with self.assertRaisesRegex(base.AdmissionBlocked, 'PACKAGE_NOT_STAGED'):
                e.collect_evidence(stage_root=self.root, correlation_id='pass001-rp23ogs-test-20261121',
                                   idempotency_key='PASS-001:RP23OGS:tailscale:1.104.7')
        fetch.assert_not_called()
        signed.assert_not_called()

    def test_stage_outside_worktree_denied(self):
        with patch.object(e.socket, 'gethostname', return_value=base.HOST), \
             patch.object(e.platform, 'system', return_value='Windows'), \
             patch.object(e.platform, 'machine', return_value='AMD64'):
            with self.assertRaisesRegex(e.EvidenceBlocked, 'STAGE_ROOT_NOT_WORKTREE_LOCAL'):
                e.collect_evidence(stage_root=self.root, correlation_id='pass001-rp23ogs-test-20261121',
                                   idempotency_key='PASS-001:RP23OGS:tailscale:1.104.7')

    def test_other_host_cannot_proceed_to_check_file_or_network(self):
        with patch.object(e.socket, 'gethostname', return_value='Noteri'), \
             patch.object(e, 'get_official_digest') as fetch:
            with self.assertRaisesRegex(base.AdmissionBlocked, 'PHYSICAL_HOST_MISMATCH'):
                e.collect_evidence(stage_root=self.root, correlation_id='pass001-rp23ogs-test-20261121',
                                   idempotency_key='PASS-001:RP23OGS:tailscale:1.104.7')
        fetch.assert_not_called()

    def test_positive_mock_never_authorizes_install(self):
        with patch.object(e.socket, 'gethostname', return_value=base.HOST), \
             patch.object(e.platform, 'system', return_value='Windows'), \
             patch.object(e.platform, 'machine', return_value='AMD64'), \
             patch.object(e.Path, 'cwd', return_value=Path(self.tmp.name)), \
             patch.object(base, 'read_staged_msi', return_value=base.SECONDARY_SHA256), \
             patch.object(e, 'get_official_digest', return_value=base.SECONDARY_SHA256.encode()), \
             patch.object(e, 'verify_windows_authenticode', return_value=True):
            result = e.collect_evidence(stage_root=self.root,
                correlation_id='pass001-rp23ogs-test-20261121',
                idempotency_key='PASS-001:RP23OGS:tailscale:1.104.7')
        self.assertEqual(result['result'], 'PACKAGE_PRECHECK_PASSED_INSTALL_STILL_BLOCKED')
        self.assertFalse(result['rollback_tested'])
        self.assertFalse(result['installation_executed'])
        self.assertFalse(result['privilege_elevation_authorized'])
        self.assertFalse(result['install_authorized_by_gate'])

    def test_checksum_only_rejects_other_host_before_request(self):
        with patch.object(e.socket, 'gethostname', return_value='Noteri'), \
             patch.object(e, 'get_official_digest') as fetch:
            self.assertEqual(e.main(['--checksum-only']), 20)
        fetch.assert_not_called()

    def test_checksum_only_fixed_host_never_authorizes_install(self):
        with patch.object(e.socket, 'gethostname', return_value=base.HOST), \
             patch.object(e.platform, 'system', return_value='Windows'), \
             patch.object(e.platform, 'machine', return_value='AMD64'), \
             patch.object(e, 'get_official_digest', return_value=base.SECONDARY_SHA256.encode()):
            self.assertEqual(e.main(['--checksum-only']), 0)

    def test_extra_options_denied_before_network(self):
        with patch.object(e, 'get_official_digest') as fetch:
            self.assertEqual(e.main(['--install']), 20)
        fetch.assert_not_called()

    def test_native_cli_no_install_commands(self):
        import inspect
        source = inspect.getsource(e)
        # Read-only adapter may mention these operations only in comments/docs.
        self.assertNotIn('import subprocess', source)
        self.assertNotIn('os.system(', source)
        self.assertNotIn('winreg.SetValue', source)
        self.assertNotIn('CreateProcess', source)
        self.assertIn('installation_executed": False', source)


if __name__ == '__main__':
    unittest.main()
