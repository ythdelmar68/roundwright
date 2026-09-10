import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from roundwright.coding_worker_state import SCHEMA, CodingProcessState, CodingCancellationState, CodingAmbiguityState

class CodingWorkerStateTests(unittest.TestCase):
    def test_public_values(self):
        self.assertEqual(SCHEMA, "roundwright-coding-tool-event/v1")
        self.assertEqual(tuple(CodingProcessState), ("started", "completed", "failed"))
        self.assertEqual(tuple(CodingCancellationState), ("not-requested", "requested", "confirmed"))
        self.assertEqual(tuple(CodingAmbiguityState), ("clear", "submission-uncertain", "terminal-uncertain"))
