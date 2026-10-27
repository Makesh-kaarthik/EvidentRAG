import unittest

from app.services.text_index import (
    extract_identifiers, query_expansion_terms, query_phrase_tokens, query_terms,
    term_frequencies, tokenize,
)


class TextIndexTests(unittest.TestCase):
    def test_tokenize_normalizes_unicode_and_removes_stop_words(self):
        self.assertEqual(tokenize("Ｔｈｅ ＡＴＴ&CK—T1059"), ["t1059"])

    def test_query_terms_expands_common_security_acronyms(self):
        self.assertEqual(query_terms("MFA login"), ["mfa", "login", "multifactor", "authentication"])

    def test_tokenizer_preserves_cve_and_attack_identifiers(self):
        values = tokenize("CVE-2024-12345 T1059.001 M1036 TA0001")
        self.assertEqual(values, ["cve-2024-12345", "t1059.001", "m1036", "ta0001"])
        self.assertEqual(extract_identifiers("See cve-2024-12345 and T1059.001"), ["CVE-2024-12345", "T1059.001"])


    def test_query_terms_normalize_attachment_and_service_plurals(self):
        terms = query_terms("spearphishing attachments and remote services")
        self.assertIn("attachments", terms)
        self.assertIn("attachment", terms)
        self.assertIn("services", terms)
        self.assertIn("service", terms)
        self.assertEqual(query_phrase_tokens("spearphishing attachments"), ["spearphishing", "attachment"])


    def test_query_terms_expand_targeted_attck_paraphrases(self):
        cases = {
            "hide and disguise malicious files": {"obfuscate", "obfuscated", "obfuscation"},
            "operating-system details": {"operating", "system", "information"},
            "internet-facing application": {"public-facing", "public"},
            "separating network zones": {"segmentation", "network"},
            "privileged accounts": {"account"},
            "enumerates user accounts": {"discovery", "enumeration"},
        }
        for query, expected_terms in cases.items():
            with self.subTest(query=query):
                self.assertTrue(expected_terms.issubset(set(query_terms(query))))

    def test_phrase_expansion_is_limited_to_attck_concepts(self):
        self.assertEqual(
            query_expansion_terms("operating-system version and host configuration"),
            ["os", "platform", "host", "system", "information", "hardware"],
        )
        self.assertEqual(
            query_expansion_terms("Active Directory domain accounts"),
            ["domain", "account", "user", "active", "directory"],
        )
        self.assertEqual(query_expansion_terms("system administrator configuration"), [])

    def test_term_frequencies_cover_title_source_id_and_text(self):
        frequencies = term_frequencies({"title": "Credential theft", "source": "MITRE", "upstream_id": "T1059", "text": "Credential theft"})
        self.assertEqual(frequencies["credential"], 2)
        self.assertEqual(frequencies["theft"], 2)
        self.assertEqual(frequencies["mitre"], 1)
        self.assertEqual(frequencies["t1059"], 1)


if __name__ == "__main__":
    unittest.main()
