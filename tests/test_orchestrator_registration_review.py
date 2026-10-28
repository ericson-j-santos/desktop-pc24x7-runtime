from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("registration_review_test", Path(__file__).resolve().parents[1] / "scripts/orchestrator_registration_review.py")
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def xml(name, sid):
    return ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<RegistrationInfo><URI>' + name + '</URI></RegistrationInfo>'
            '<Principals><Principal><UserId>' + sid + '</UserId><LogonType>S4U</LogonType></Principal></Principals>'
            '<Triggers><BootTrigger/></Triggers></Task>').encode()


class TaskIdentityTests(unittest.TestCase):
    def test_identity_compared_without_exporting_sid(self):
        sid = "S-1-5-21-111-222-333-1001"
        name = r"\Automation\DesktopPc24x7RuntimeWatchdog"
        result = m.parse_task(xml(name, sid), name, sid, None)
        assert result["process_sid_matches_principal"] is True
        assert result["s4u"] is True
        assert sid not in str(result)


    def test_other_task_rejected_and_other_sid_is_not_equivalent(self):
        name = r"\Automation\DesktopPc24x7RuntimeWatchdog"
        with self.assertRaises(ValueError):
            m.parse_task(xml(r"\AnotherTask", "S-1-5-1"), name, "S-1-5-1", None)
        result = m.parse_task(xml(name, "S-1-5-1"), name, "S-1-5-2", None)
        assert result["process_sid_matches_principal"] is False


if __name__ == '__main__':
    unittest.main()
