import unittest

from app.services.evidence_intelligence import evaluate


class EvidenceIntelligenceTests(unittest.TestCase):
    def test_empty_results_are_insufficient(self):
        self.assertEqual(evaluate("CVE-2024-1234", []), {"sufficient": False, "relevance": 0.0, "coverage": 0.0, "confidence": 0.0})

    def test_exact_identifier_is_sufficient_even_with_low_heuristic_score(self):
        result = evaluate("CVE-2024-1234", [{"relevance": 0.0, "exact_identifier": True, "_tokens": set()}])
        self.assertTrue(result["sufficient"])
        self.assertEqual(result["confidence"], 0.0)

    def test_relevant_evidence_with_coverage_passes_gate(self):
        result = evaluate("credential theft", [{"relevance": 0.8, "_tokens": {"credential", "theft"}}])
        self.assertTrue(result["sufficient"])
        self.assertEqual(result["coverage"], 1.0)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_low_coverage_fails_gate_and_values_are_clamped(self):
        result = evaluate("alpha bravo charlie delta echo", [{"relevance": 4.0, "_tokens": {"alpha"}}])
        self.assertFalse(result["sufficient"])
        self.assertEqual(result["relevance"], 1.0)
        self.assertLessEqual(result["coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
