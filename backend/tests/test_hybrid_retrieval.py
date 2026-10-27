import unittest
from unittest.mock import patch

from app.services.hybrid_retrieval import retrieve
from app.services.text_index import term_frequencies


class FakeCursor(list):
    def limit(self, _count):
        return FakeCursor(self[:_count])

    def sort(self, keys):
        values = list(self)
        for field, direction in reversed(keys):
            parts = field.split(".")
            values.sort(
                key=lambda item: item.get(parts[0], {}).get(parts[1], 0),
                reverse=direction < 0,
            )
        return FakeCursor(values)


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    def find(self, _query, _projection):
        return FakeCursor(self.documents)


class HybridRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.documents = [
            {"upstream_id": "T1059", "title": "Command execution", "source": "ATT&CK", "text": "Adversaries execute commands through a command shell."},
            {"upstream_id": "T1082", "title": "System discovery", "source": "ATT&CK", "text": "Adversaries observe T1059 command shell activity."},
        ]
        for document in self.documents:
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
        self.collection = FakeCollection(self.documents)

    def test_bm25_ranks_matching_document_first(self):
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": self.collection}):
            results = retrieve("command shell execution", 5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["upstream_id"], "T1059")
        self.assertGreater(results[0]["bm25_score"], results[1]["bm25_score"])
        self.assertIn("command", results[0]["_tokens"])

    def test_exact_identifier_boost_takes_priority(self):
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": self.collection}):
            results = retrieve("T1059", 5)
        self.assertEqual(results[0]["upstream_id"], "T1059")
        self.assertTrue(results[0]["exact_identifier"])
        self.assertEqual(len(results), 2)
        self.assertFalse(results[1]["exact_identifier"])


    def test_named_remote_services_technique_outranks_lateral_movement_tactic(self):
        documents = [
            {
                "upstream_id": "T1021", "source_type": "attack-pattern",
                "title": "Remote Services (T1021)", "source": "ATT&CK",
                "text": "Remote Services accept SSH, VNC, and RDP connections for lateral movement.",
            },
            {
                "upstream_id": "TA0008", "source_type": "x-mitre-tactic",
                "title": "Lateral Movement (TA0008)", "source": "ATT&CK",
                "text": "Lateral movement describes movement through a compromised network using remote services.",
            },
        ]
        for document in documents:
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
        collection = FakeCollection(documents)
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": collection}):
            results = retrieve("Which ATT&CK technique uses remote services for lateral movement?", 5)
        self.assertEqual(results[0]["upstream_id"], "T1021")

    def test_no_query_match_returns_no_results(self):
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": self.collection}):
            self.assertEqual(retrieve("quantum banana", 5), [])

    def test_operating_system_configuration_paraphrase_ranks_system_discovery(self):
        documents = [
            {"upstream_id": "T1082", "source_type": "attack-pattern", "title": "System Information Discovery (T1082)", "source": "ATT&CK", "text": "Gather detailed information about the operating system and hardware, including version, patches, and architecture."},
            {"upstream_id": "M1028", "source_type": "course-of-action", "title": "Operating System Configuration (M1028)", "source": "ATT&CK", "text": "Change default operating system configurations."},
            {"upstream_id": "T1592", "source_type": "attack-pattern", "title": "Gather Victim Host Information (T1592)", "source": "ATT&CK", "text": "Collect information about a victim host."},
        ]
        for document in documents:
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
        collection = FakeCollection(documents)
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": collection}):
            results = retrieve("Which technique identifies a computer's operating-system version and host configuration?", 5)
        self.assertEqual(next(result["upstream_id"] for result in results if result["upstream_id"] == "T1082"), "T1082")
        self.assertLessEqual(next(index for index, result in enumerate(results, start=1) if result["upstream_id"] == "T1082"), 3)

    def test_active_directory_account_listing_ranks_domain_account_technique(self):
        documents = [
            {"upstream_id": "T1087.002", "source_type": "attack-pattern", "title": "Domain Account (T1087.002)", "source": "ATT&CK", "text": "Adversaries may attempt to get a listing of domain accounts and enumerate Active Directory users."},
            {"upstream_id": "T1136.002", "source_type": "attack-pattern", "title": "Domain Account (T1136.002)", "source": "ATT&CK", "text": "Create a domain account for persistence."},
            {"upstream_id": "M1015", "source_type": "course-of-action", "title": "Active Directory Configuration (M1015)", "source": "ATT&CK", "text": "Configure Active Directory securely."},
        ]
        for document in documents:
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
        collection = FakeCollection(documents)
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": collection}):
            results = retrieve("Which sub-technique lists user accounts in an Active Directory domain?", 5)
        self.assertEqual(next(result["upstream_id"] for result in results if result["upstream_id"] == "T1087.002"), "T1087.002")
        self.assertLessEqual(next(index for index, result in enumerate(results, start=1) if result["upstream_id"] == "T1087.002"), 3)

    def test_multi_stage_incident_retrieves_each_matching_technique(self):
        documents = [
            {
                "upstream_id": "T1003.001", "source_type": "attack-pattern",
                "title": "OS Credential Dumping: LSASS Memory", "source": "ATT&CK",
                "text": "Read LSASS memory to extract cached credentials and password hashes.",
            },
            {
                "upstream_id": "T1059.001", "source_type": "attack-pattern",
                "title": "Command and Scripting Interpreter: PowerShell", "source": "ATT&CK",
                "text": "Adversaries may use PowerShell commands and scripts to execute actions.",
            },
            {
                "upstream_id": "T1021.001", "source_type": "attack-pattern",
                "title": "Remote Services: Remote Desktop Protocol", "source": "ATT&CK",
                "text": "Use valid accounts to connect to another workstation over Remote Desktop for lateral movement.",
            },
        ]
        for document in documents:
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
        collection = FakeCollection(documents)
        query = (
            "An attacker gains access to a Windows workstation, then uses PowerShell "
            "to read the LSASS process and extract cached credentials. They use a "
            "stolen domain account to connect to another workstation over Remote Desktop."
        )
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": collection}):
            results = retrieve(query, 5)
        self.assertTrue({"T1003.001", "T1059.001", "T1021.001"}.issubset(
            {result["upstream_id"] for result in results}
        ))

    def test_empty_collection_returns_no_results(self):
        with patch("app.services.hybrid_retrieval.get_database", return_value={"knowledge_chunks": FakeCollection([])}):
            self.assertEqual(retrieve("CVE-2024-1234", 5), [])


if __name__ == "__main__":
    unittest.main()
