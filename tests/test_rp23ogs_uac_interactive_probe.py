import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from scripts import rp23ogs_uac_interactive_probe as x

class ProbeTests(unittest.TestCase):
    def test_target_only(self):
        x.validate_host(hostname=x.TARGET, system="Windows", machine="AMD64")
        for host, system, machine in [("NOTERI", "Windows", "AMD64"),
                                      (x.TARGET, "Linux", "AMD64"),
                                      (x.TARGET, "Windows", "ARM64")]:
            with self.assertRaisesRegex(x.ProbeBlocked, "HOST_OR_PLATFORM_DENIED"):
                x.validate_host(hostname=host, system=system, machine=machine)

    def facts(self, **overrides):
        base = {"process_session_id": 1, "console_session_id": 1,
                "active_console_session": True, "window_station_visible": True}
        return base | overrides

    def test_possible_is_not_proof_of_uac(self):
        result = x.classify(self.facts())
        self.assertTrue(result["interactive_uac_ready_for_this_process"])
        self.assertEqual(result["result"], "INTERACTIVE_PROCESS_CONTEXT_POSSIBLE_NOT_UAC_PROVEN")
        self.assertFalse(result["uac_prompt_sent"])
        self.assertFalse(result["installation_executed"])

    def test_background_process_session_denied(self):
        result = x.classify(self.facts(process_session_id=0))
        self.assertFalse(result["interactive_uac_ready_for_this_process"])
        self.assertFalse(result["same_session_as_active_console"])

    def test_disconnected_console_denied(self):
        result = x.classify(self.facts(active_console_session=False))
        self.assertFalse(result["interactive_uac_ready_for_this_process"])

    def test_hidden_window_station_denied(self):
        result = x.classify(self.facts(window_station_visible=False))
        self.assertFalse(result["interactive_uac_ready_for_this_process"])

    def test_no_console_denied(self):
        result = x.classify(self.facts(console_session_id=None))
        self.assertFalse(result["interactive_uac_ready_for_this_process"])

    def test_no_usernames_or_sensitive_data(self):
        data = x.classify(self.facts())
        self.assertEqual(set(data), {"contract", "host", "process_session_id", "console_session_id",
                 "same_session_as_active_console", "active_console_session", "window_station_visible",
                 "interactive_uac_ready_for_this_process", "result", "installation_executed",
                 "uac_prompt_sent", "credentials_read"})

    def test_main_fails_closed_other_host(self):
        buf = io.StringIO()
        with patch.object(x.socket, "gethostname", return_value="NOTERI"),\
             patch.object(x.platform, "system", return_value="Windows"),\
             patch.object(x.platform, "machine", return_value="AMD64"),\
             redirect_stdout(buf):
            self.assertEqual(x.main(), 20)
        self.assertEqual(json.loads(buf.getvalue())["result"], "BLOCKED")

    def test_main_with_mock_context_no_uac(self):
        buf = io.StringIO()
        with patch.object(x.socket, "gethostname", return_value=x.TARGET),\
             patch.object(x.platform, "system", return_value="Windows"),\
             patch.object(x.platform, "machine", return_value="AMD64"),\
             patch.object(x, "query_session_facts", return_value=self.facts(process_session_id=0)),\
             redirect_stdout(buf):
            self.assertEqual(x.main(), 0)
        self.assertFalse(json.loads(buf.getvalue())["interactive_uac_ready_for_this_process"])

if __name__ == "__main__":
    unittest.main()
