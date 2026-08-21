import unittest
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from core import analyze_log_file


class SecurityLogAgentTests(unittest.TestCase):
    def test_attack_sample(self):
        result = analyze_log_file(BASE / "sample_attack_logs.csv")
        self.assertEqual(result["broken_count"], 2)
        self.assertEqual(result["overall_risk"]["risk"], "HIGH")
        self.assertEqual(result["overall_risk"]["score"], 52)
        types = {d["type"] for d in result["detections"]}
        self.assertIn("USER_BRUTE_FORCE", types)
        self.assertIn("MULTI_ACCOUNT_ATTACK", types)
        self.assertIn("SUCCESS_AFTER_FAILURE", types)

    def test_normal_sample(self):
        result = analyze_log_file(BASE / "sample_normal_logs.csv")
        self.assertEqual(result["broken_count"], 0)
        self.assertEqual(result["overall_risk"]["risk"], "LOW")
        self.assertEqual(result["overall_risk"]["score"], 0)
        self.assertEqual(len(result["detections"]), 0)


if __name__ == "__main__":
    unittest.main()
