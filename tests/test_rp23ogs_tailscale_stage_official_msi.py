"""Negative, replay, and no-overwrite tests; never downloads real MSI."""
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import rp23ogs_tailscale_admission as a
from scripts import rp23ogs_tailscale_windows_evidence as e
from scripts import rp23ogs_tailscale_stage_official_msi as g

FAKE_MSI = b'TEST BYTES; NOT AN INSTALLER' * 46000
FAKE_DIGEST = hashlib.sha256(FAKE_MSI).hexdigest()


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.stage = self.root / 'tailscale-pass001-staging'
        self.package = self.stage / a.MSI_NAME

    def good(self):
        from contextlib import ExitStack
        s = ExitStack()
        self.addCleanup(s.close)
        s.enter_context(patch.object(g.socket, 'gethostname', return_value=a.HOST))
        s.enter_context(patch.object(g.platform, 'system', return_value='Windows'))
        s.enter_context(patch.object(g.platform, 'machine', return_value='AMD64'))
        s.enter_context(patch.object(g.Path, 'cwd', return_value=self.root))
        s.enter_context(patch.object(a, 'SECONDARY_SHA256', FAKE_DIGEST))
        s.enter_context(patch.object(e, 'get_official_digest', return_value=FAKE_DIGEST.encode()))
        return s

    def test_happy_stage_is_pinned_and_no_install(self):
        self.good()
        result = g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(FAKE_MSI))
        self.assertEqual(result['result'], 'STAGED_VERIFIED_INSTALL_BLOCKED')
        self.assertEqual(self.package.read_bytes(), FAKE_MSI)
        self.assertFalse(result['installation_executed'])
        self.assertFalse(result['privilege_elevation_authorized'])
        self.assertFalse(result['rollback_tested'])
        self.assertEqual(list(self.stage.glob('*.part')), [])

    def test_replay_does_not_fetch_or_write(self):
        self.good()
        g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(FAKE_MSI))
        before = self.package.stat().st_mtime_ns
        def fail_fetch():
            raise AssertionError('Should never download an existing verified MSI')
        result = g.stage_once(worktree=self.root, response_factory=fail_fetch)
        self.assertEqual(result['result'], 'ALREADY_STAGED_VERIFIED')
        self.assertEqual(self.package.stat().st_mtime_ns, before)

    def test_wrong_file_not_overwritten(self):
        self.good()
        self.stage.mkdir()
        self.package.write_bytes(b'bad previously staged file')
        with self.assertRaises(a.AdmissionBlocked):
            g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(FAKE_MSI))
        self.assertEqual(self.package.read_bytes(), b'bad previously staged file')

    def test_hash_failure_does_not_publish_msi(self):
        self.good()
        with self.assertRaisesRegex(g.StageBlocked, 'PACKAGE_HASH_MISMATCH'):
            g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(b'z' * 1010000))
        self.assertFalse(self.package.exists())
        self.assertEqual(list(self.stage.glob('*.part')), [])

    def test_too_small_does_not_publish(self):
        self.good()
        with self.assertRaisesRegex(g.StageBlocked, 'PACKAGE_SIZE_INVALID'):
            g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(b'bad'))
        self.assertFalse(self.package.exists())

    def test_wrong_host_does_not_fetch(self):
        with patch.object(g.socket, 'gethostname', return_value='Noteri'), \
             patch.object(e, 'get_official_digest') as f:
            with self.assertRaisesRegex(a.AdmissionBlocked, 'PHYSICAL_HOST_MISMATCH'):
                g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(FAKE_MSI))
        f.assert_not_called()

    def test_wrong_worktree_does_not_fetch(self):
        with patch.object(g.socket, 'gethostname', return_value=a.HOST), \
             patch.object(g.platform, 'system', return_value='Windows'), \
             patch.object(g.platform, 'machine', return_value='AMD64'), \
             patch.object(e, 'get_official_digest') as f:
            with self.assertRaisesRegex(g.StageBlocked, 'WORKTREE_IDENTITY_MISMATCH'):
                g.stage_once(worktree=self.root, response_factory=lambda: io.BytesIO(FAKE_MSI))
        f.assert_not_called()

    def test_request_arguments_rejected(self):
        self.assertEqual(g.main(['--install']), 20)

    def test_url_fixed_and_redirect_denied(self):
        class Reply(io.BytesIO):
            def getcode(self): return 200
            def geturl(self): return 'https://other-site.invalid/installer.msi'
        class Opener:
            def open(self, request, timeout):
                self.url = request.full_url
                return Reply(FAKE_MSI)
        opener = Opener()
        with patch.object(g.urllib.request,'build_opener',return_value=opener):
            with self.assertRaisesRegex(g.StageBlocked, 'OFFICIAL_PACKAGE_ORIGIN_MISMATCH'):
                g._open_official_msi()
        self.assertEqual(opener.url, a.OFFICIAL_ORIGIN)

    def test_readonly_result_never_claims_backup_proven(self):
        self.good()
        res = g.stage_once(worktree=self.root,response_factory=lambda:io.BytesIO(FAKE_MSI))
        self.assertNotIn('backup_verified',res)
        self.assertFalse(res['rollback_tested'])


if __name__ == '__main__':
    unittest.main()
