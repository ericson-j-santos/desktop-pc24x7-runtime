"""Risk3 exact UAC transaction: fail-closed and deterministic non-install tests."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import rp23ogs_tailscale_install_uac as t


class InstallUacContractTests(unittest.TestCase):
    def test_offline_cli_denies_prepare(self):
        if os.name != "nt":
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                self.assertEqual(t.main(["--prepare"]), 20)
            self.assertIn("HOST_NOT_RP23OGS_WINDOWS", buf.getvalue())

    def test_reject_unlisted_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                t.main(["--install", "--url", "https://malicious.invalid"])

    def test_requires_confirmation(self):
        with self.assertRaisesRegex(t.InstallBlocked, "INSTALL_CONFIRMATION_INVALID"):
            t.request_uac("install", "wrong")
        with self.assertRaisesRegex(t.InstallBlocked, "ROLLBACK_CONFIRMATION_INVALID"):
            t.request_uac("rollback", "wrong")

    def test_rejects_unknown_action(self):
        with self.assertRaisesRegex(t.InstallBlocked, "OPERATION_DENIED"):
            t.request_uac("funnel", "whatever")
        with self.assertRaisesRegex(t.InstallBlocked, "OPERATION_DENIED"):
            t.build_msiexec_args("serve", Path("a.msi"))

    def test_requires_absent_preinstall(self):
        absent = dict(service=False, uninstall=False, program_files=False, program_data=False, user_data=False)
        t.require_absent(absent)
        for key in absent:
            with self.subTest(key=key):
                changed = {**absent, key: True}
                with self.assertRaisesRegex(t.InstallBlocked, "PREEXISTING_TAILSCALE"):
                    t.require_absent(changed)

    def test_partial_baseline_rejected(self):
        with self.assertRaisesRegex(t.InstallBlocked, "BASELINE_INCOMPLETE"):
            t.require_absent({"service": False})

    def test_msiexec_pinned_to_windows_system32(self):
        self.assertEqual(str(t.INSTALLER).casefold(), r"c:\windows\system32\msiexec.exe")
        self.assertEqual(t.SOURCE_SHA, "676b5b32fdd1aeaee90d8e8f38e222635b216fbdfbf877bf01cb1d7cda330ec5")

    def test_install_command_prevents_gui_login_and_restart(self):
        package = Path("C:/test/tailscale-setup-1.104.7-amd64.msi")
        command = t.build_msiexec_args("install", package)
        self.assertIn("/i", command)
        self.assertIn("/qn", command)
        self.assertIn("/norestart", command)
        self.assertIn("TS_NOLAUNCH=1", command)
        self.assertIn("TS_UNATTENDEDMODE=never", command)
        self.assertNotIn("tailscale up", command)
        self.assertNotIn("funnel", command.lower())

    def test_rollback_uses_same_msi_and_norestart(self):
        package = Path("C:/test/tailscale-setup-1.104.7-amd64.msi")
        c = t.build_msiexec_args("rollback", package)
        self.assertIn('/x', c)
        self.assertIn('/norestart', c)
        self.assertIn(str(package), c)
        self.assertNotIn('TS_NOLAUNCH', c)

    def test_preflight_rejects_missing_backup(self):
        with patch.object(t, 'require_host'), patch.object(t, 'fixed_msi', return_value=Path('/definitely/not/present/file.msi')):
            with self.assertRaisesRegex(t.InstallBlocked, 'MSI_BACKUP_NOT_PRESENT'):
                t.preflight()

    def test_rollback_does_not_invoke_uac_when_service_absent(self):
        with patch.object(t, 'load_snapshot', return_value={}), \
             patch.object(t, 'read_verified_msi'), \
             patch.object(t, 'fixed_msi', return_value=Path('/test/file.msi')), \
             patch.object(t, 'preinstall_state', return_value={'service':False}):
            with self.assertRaisesRegex(t.InstallBlocked, 'NO_INSTALLED_STATE_FOR_ROLLBACK'):
                t.request_uac('rollback', t.CONFIRM_ROLLBACK)

    def test_install_does_not_invoke_uac_without_preflight(self):
        with patch.object(t, 'preflight', side_effect=t.InstallBlocked('MSI_BACKUP_NOT_PRESENT')):
            with self.assertRaisesRegex(t.InstallBlocked, 'MSI_BACKUP_NOT_PRESENT'):
                t.request_uac('install', t.CONFIRM_INSTALL)

    def test_success_preflight_proves_no_install(self):
        flags = dict(service=False, uninstall=False, program_files=False, program_data=False, user_data=False)
        with patch.object(t, 'require_host'), \
             patch.object(t, 'fixed_msi', return_value=Path(__file__)), \
             patch.object(t, 'load_snapshot', return_value={'preinstall':flags}), \
             patch.object(t, 'read_verified_msi'), \
             patch.object(t, 'preinstall_state', return_value=flags):
            res = t.preflight()
        self.assertEqual(res['result'], 'READY_FOR_EXACT_UAC_ACTION_NOT_INSTALLED')
        self.assertFalse(res['rollback_tested'])
        self.assertFalse(res['install_executed'])

    def test_main_blocks_already_elevated_no_shell_bypass(self):
        with patch.object(t, 'preflight', return_value={}), \
             patch.object(t, 'INSTALLER') as exe, \
             patch.object(t, 'is_admin', return_value=True), \
             patch.object(t, 'require_specific_risk3_action'):
            exe.is_file.return_value = True
            exe.parent = Path('C:' + chr(92) + 'Windows' + chr(92) + 'System32')
            with self.assertRaisesRegex(t.InstallBlocked, 'ALREADY_ELEVATED'):
                t.request_uac('install', t.CONFIRM_INSTALL)

    def test_risk3_requires_exact_owner_allowlist(self):
        with patch.object(t, 'require_host'), patch.dict(os.environ, {"LOCALAPPDATA": "/nonexistent/path"}):
            with self.assertRaisesRegex(t.InstallBlocked, 'RISK3_EXACT_ACTION_REQUIRED'):
                t.require_specific_risk3_action('install', t.CONFIRM_INSTALL)

    def test_risk3_rejects_unlisted_operation(self):
        with patch.object(t, 'require_host'):
            with self.assertRaisesRegex(t.InstallBlocked, 'RISK3_OPERATION_DENIED'):
                t.require_specific_risk3_action('activate-tailnet', 'anything')

    def test_untrusted_or_other_pc_denied(self):
        with patch.object(t.socket, 'gethostname', return_value='Noteri'):
            with self.assertRaisesRegex(t.InstallBlocked, 'HOST_NOT_RP23OGS_WINDOWS'):
                t.require_host()

    def test_no_generic_subprocess_or_shell(self):
        src=Path(t.__file__).read_text(encoding='utf-8')
        self.assertNotIn('shell=True', src)
        self.assertNotIn('os.system(', src)
        self.assertNotIn('powershell', src.lower())
        self.assertNotIn('tailscale up', src.lower())
        self.assertNotIn('tailscale serve', src.lower())
        self.assertNotIn('tailscale funnel', src.lower())


class UacDiagnosticReceiptTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name) / "PASS001" / "TailscaleInstallerV1"
        self.cache.mkdir(parents=True)
        patcher = patch.object(t, 'fixed_cache', return_value=self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.id = "e" * 32

    def test_receipt_absent_is_not_installation_evidence(self):
        record = t.read_uac_diagnostic()
        self.assertEqual(record['result'], 'NO_DIAGNOSTIC_RECEIPT')
        self.assertFalse(record['installation_comproved'])

    def test_journal_checkpoint_roundtrip_is_only_diagnostic(self):
        t.write_uac_diagnostic('install', self.id, 'launch_requested')
        data = t.read_uac_diagnostic()
        self.assertEqual(data['phase'], 'launch_requested')
        self.assertEqual(data['uac_approved'], 'NOT_ATTESTED')
        self.assertFalse(data['installation_comproved'])

    def test_timeout_checkpoint_is_not_installation_success(self):
        t.write_uac_diagnostic('install', self.id, 'wait_started')
        t.write_uac_diagnostic('install', self.id,
                               'wait_timeout_process_may_continue', detail='wait_timeout')
        info = t.read_uac_diagnostic()
        self.assertEqual(info['phase'], 'wait_timeout_process_may_continue')
        self.assertEqual(info['detail'], 'wait_timeout')
        self.assertFalse(info['installation_comproved'])
        self.assertEqual(list(self.cache.iterdir())[0].name, t.UAC_RECEIPT_NAME)

    def test_unknown_stage_fails_without_file(self):
        with self.assertRaisesRegex(t.InstallBlocked, 'PHASE_INVALID'):
            t.write_uac_diagnostic('install', self.id, 'tailnet_activated')
        self.assertFalse(t.uac_receipt_path().exists())

    def test_unknown_detail_fails_without_file(self):
        with self.assertRaisesRegex(t.InstallBlocked, 'DETAIL_INVALID'):
            t.write_uac_diagnostic('install', self.id, 'wait_started', detail='secret=abc')
        self.assertFalse(t.uac_receipt_path().exists())

    def test_corrupt_journal_fail_closed(self):
        t.uac_receipt_path().write_text('not-json', encoding='utf-8')
        with self.assertRaisesRegex(t.InstallBlocked, 'READ_BLOCKED'):
            t.read_uac_diagnostic()

    def test_tampered_detail_is_not_echoed(self):
        import json
        t.write_uac_diagnostic('install', self.id, 'wait_started')
        path = t.uac_receipt_path()
        data = json.loads(path.read_text(encoding='utf-8'))
        data['detail'] = 'token=private_do_not_print'
        path.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaisesRegex(t.InstallBlocked, 'READ_BLOCKED'):
            t.read_uac_diagnostic()

    def test_diagnose_cli_read_only(self):
        with patch.object(t, 'request_uac', side_effect=AssertionError('UAC should never run')):
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = t.main(['--diagnose'])
        self.assertEqual(rc, 0)
        self.assertIn('NO_DIAGNOSTIC_RECEIPT', buf.getvalue())
        self.assertFalse(t.uac_receipt_path().exists())

    def test_diagnose_rejects_confirmation(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = t.main(['--diagnose', '--confirm', 'BAD'])
        self.assertEqual(rc, 20)
        self.assertFalse(t.uac_receipt_path().exists())

    def test_wait_status_classification(self):
        self.assertEqual(t.classify_wait_status(0), 'completed')
        self.assertEqual(t.classify_wait_status(258), 'timeout')
        self.assertEqual(t.classify_wait_status(0xffffffff), 'failed')
        self.assertEqual(t.classify_wait_status(128), 'unexpected')


if __name__ == "__main__":
    unittest.main()
