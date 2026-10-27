import unittest

from app.services.citation_validation import validate_citations


class CitationValidationTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {
            "E1": "CISA KEV CVE-2024-12345: Example Server remote code execution vulnerability. Apply vendor updates.",
            "E2": "Vendor required action: apply updates to affected Example Server systems.",
        }

    def test_accepts_cited_claims_supported_by_each_source(self):
        answer = (
            "CVE-2024-12345 affects Example Server and permits remote code execution [E1]. "
            "Apply vendor updates to affected Example Server systems [E2]."
        )
        self.assertTrue(validate_citations(answer, self.evidence))

    def test_rejects_answer_without_citation(self):
        self.assertFalse(validate_citations("The vulnerability affects Example Server.", self.evidence))

    def test_rejects_uncited_sentence_even_when_another_sentence_is_cited(self):
        answer = "The flaw affects Example Server [E1]. It is exploited worldwide."
        self.assertFalse(validate_citations(answer, self.evidence))

    def test_rejects_unknown_or_mixed_validity_labels(self):
        self.assertFalse(validate_citations("The flaw affects Example Server [E3].", self.evidence))
        self.assertFalse(validate_citations("The flaw affects Example Server [E1] [E9].", self.evidence))

    def test_rejects_irrelevant_or_extra_citations(self):
        answer = "Remote code execution affects Example Server [E1] [E2]."
        evidence_with_unrelated_source = {
            "E1": self.evidence["E1"],
            "E2": "Windows Defender signatures are refreshed each week.",
        }
        self.assertFalse(validate_citations(answer, evidence_with_unrelated_source))
        self.assertFalse(validate_citations("A global outage is certain [E1].", self.evidence))

    def test_rejects_identifiers_not_present_in_cited_source(self):
        answer = "CVE-2024-99999 affects Example Server [E1]."
        self.assertFalse(validate_citations(answer, self.evidence))

    def test_rejects_unsupported_numbers(self):
        evidence = {"E1": "CVE-2024-12345 affects Example Server version 1.2."}
        answer = "CVE-2024-12345 affects Example Server version 2.0 [E1]."
        self.assertFalse(validate_citations(answer, evidence))

    def test_rejects_empty_answer_or_missing_evidence(self):
        self.assertFalse(validate_citations("", self.evidence))
        self.assertFalse(validate_citations("The flaw affects Example Server [E1].", {}))


if __name__ == "__main__":
    unittest.main()
