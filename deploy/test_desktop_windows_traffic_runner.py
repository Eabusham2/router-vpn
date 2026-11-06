"""Exact mandatory inventory for native duplicate failure observations."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("traffic_gate", Path(__file__).with_name("test_desktop_windows_traffic.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

class DuplicateObservationInventory(unittest.TestCase):
    def test_exact_parent_and_all_real_native_leaves_required(self):
        names = (GATE.DUPLICATE_OBSERVATION_ROOT, *(GATE.DUPLICATE_OBSERVATION_ROOT + "/" + leaf for leaf in GATE.DUPLICATE_OBSERVATION_LEAVES))
        rows = ["--- PASS: " + name + " (0.01s)\n" for name in names]
        GATE.require_duplicate_observations("".join(rows))
        self.assertIn(GATE.DUPLICATE_OBSERVATION_ROOT, GATE.REQUIRED)
        for i in range(len(rows)):
            for output in ("".join(rows[:i] + rows[i+1:]), "".join(rows + [rows[i]]), "".join(rows).replace(rows[i], "expected: " + rows[i])):
                with self.assertRaises(ValueError):
                    GATE.require_duplicate_observations(output)

if __name__ == "__main__":
    unittest.main()
