import importlib.util
from pathlib import Path
import unittest
SPEC = importlib.util.spec_from_file_location("activation_inventory_test", Path(__file__).resolve().parents[1] / "scripts/orchestrator_activation_inventory.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class SafeClassificationTests(unittest.TestCase):
    def test_error_categories_do_not_export_raw_text(self):
        self.assertEqual(m.failure_kind(b"ERROR: Access is denied."), "access_denied")
        self.assertEqual(m.failure_kind(b"The system cannot find the file specified."), "not_found")
        self.assertEqual(m.failure_kind(b"RPC server unavailable"), "rpc_unavailable")
        self.assertEqual(m.failure_kind(b"private-arbitrary-error"), "unclassified")

if __name__ == "__main__":
    unittest.main()
