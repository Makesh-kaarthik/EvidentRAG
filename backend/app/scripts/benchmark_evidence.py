"""Offline benchmark for evidence sufficiency policies on the processed corpus.

Run from backend with:
    .\\python313\\python.exe -m app.scripts.benchmark_evidence

The script reuses production retrieval and gate code while supplying a small
in-memory Mongo-compatible read adapter, so no live database or model key is
needed. Output is a JSON summary and a per-case CSV under Datasets/processed.
"""

from __future__ import annotations

import csv
import argparse
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch

from app.core.config import settings
from app.core.database import close_mongodb_connection, connect_to_mongodb
from app.services.evidence_intelligence import evaluate
from app.services.hybrid_retrieval import retrieve
from app.services.text_index import term_frequencies


ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = ROOT / "Datasets" / "processed" / "index_documents.jsonl"
OUTPUT_DIR = ROOT / "Datasets" / "processed"
POLICIES = ("no_gate", "relevance_only", "coverage_only", "current")
REPEATS = 5

# Gold labels are ATT&CK Enterprise 20 IDs present in this project's corpus.
CASES = [
    ("lsass_credential_dumping", "PowerShell reads LSASS memory to collect password hashes and cached credentials.", "T1003.001"),
    ("powershell_execution", "An encoded PowerShell script executes commands on a compromised endpoint.", "T1059.001"),
    ("rdp_valid_account", "A stolen employee account connects to another workstation over Remote Desktop.", "T1021.001"),
    ("scheduled_task_logon", "Malware creates a scheduled task that runs whenever a user logs on.", "T1053.005"),
    ("targeted_email_attachment", "A weaponized attachment arrives in a targeted email to gain initial access.", "T1566.001"),
    ("clear_windows_logs", "The intruder uses wevtutil to erase Windows Security event records.", "T1685.005"),
    ("disable_antivirus", "Malware disables antivirus protection and tampers with endpoint defenses.", "T1685"),
    ("windows_service_backdoor", "The attacker installs a malicious Windows service to maintain a backdoor.", "T1543.003"),
    ("archive_via_utility", "Collected files are compressed into a password-protected archive using 7-Zip.", "T1560.001"),
    ("system_information", "The operator runs systeminfo to learn the host operating system and hardware configuration.", "T1082"),
    ("rdp_lateral_movement", "An attacker uses RDP to move laterally from one Windows host to another.", "T1021.001"),
    ("browser_credential_theft", "Malware steals credentials from browser and operating-system credential caches.", "T1555"),
    ("out_weather", "What will the weather be in Mumbai tomorrow?", None),
    ("out_recipe", "Give me a recipe for paneer butter masala.", None),
    ("out_bicycle", "How do I repair a broken bicycle chain?", None),
    ("out_capital", "What is the capital city of Japan?", None),
    ("out_physics", "Explain quantum entanglement in simple terms.", None),
    ("out_sports", "Who won the 2026 World Cup?", None),
]


class Cursor(list):
    def limit(self, count: int) -> "Cursor":
        return Cursor(self[:count])

    def sort(self, keys: list[tuple[str, int]]) -> "Cursor":
        values = list(self)
        for path, direction in reversed(keys):
            parent, key = path.split(".", 1)
            values.sort(
                key=lambda item: item.get(parent, {}).get(key, 0),
                reverse=direction < 0,
            )
        return Cursor(values)


class LocalCollection:
    """Small read-only adapter implementing the find operations used by retrieve."""

    def __init__(self, documents: list[dict]):
        self.documents = documents
        self.by_id = {doc["upstream_id"]: doc for doc in documents if doc.get("upstream_id")}
        self.by_term: dict[str, list[dict]] = defaultdict(list)
        for document in documents:
            for term in document["term_frequency"]:
                self.by_term[term].append(document)

    @staticmethod
    def _matches_scope(document: dict, query: dict) -> bool:
        source_scope = query.get("source_type")
        if isinstance(source_scope, dict) and "$in" in source_scope:
            if document.get("source_type") not in source_scope["$in"]:
                return False
        elif source_scope and document.get("source_type") != source_scope:
            return False
        if query.get("text", {}).get("$exists") and not document.get("text"):
            return False
        return True

    def find(self, query: dict, _projection: dict) -> Cursor:
        candidates: dict[str, dict] = {}

        def add_term(path: str) -> None:
            term = path.removeprefix("term_frequency.")
            for doc in self.by_term.get(term, ()):
                candidates[doc["source_id"]] = doc

        if "upstream_id" in query and "$or" not in query:
            value = query["upstream_id"]
            ids = value.get("$in", []) if isinstance(value, dict) else [value]
            candidates.update({item: self.by_id[item] for item in ids if item in self.by_id})
        elif "$or" in query:
            for clause in query["$or"]:
                if "upstream_id" in clause:
                    for item in clause["upstream_id"].get("$in", []):
                        if item in self.by_id:
                            candidates[item] = self.by_id[item]
                for field in clause:
                    if field.startswith("term_frequency."):
                        add_term(field)
        else:
            for field in query:
                if field.startswith("term_frequency."):
                    add_term(field)

        records = [doc for doc in candidates.values() if self._matches_scope(doc, query)]
        # Direct anchor filters require that anchor; the broad $or query does not.
        direct_terms = [field for field in query if field.startswith("term_frequency.")]
        if direct_terms:
            records = [
                doc for doc in records
                if all(doc["term_frequency"].get(field.removeprefix("term_frequency."), 0) for field in direct_terms)
            ]
        return Cursor(records)


def load_attack_documents() -> list[dict]:
    documents = []
    with CORPUS_PATH.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            document = json.loads(line)
            if document.get("source_type") != "attack-pattern":
                continue
            document["term_frequency"] = term_frequencies(document)
            document["token_count"] = sum(document["term_frequency"].values())
            documents.append(document)
    return documents


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="query the configured live MongoDB collection instead of the local processed corpus",
    )
    args = parser.parse_args()
    if args.live:
        database = connect_to_mongodb()
        collection = database[settings.knowledge_collection]
        document_count = collection.count_documents({"source_type": "attack-pattern"})
    else:
        documents = load_attack_documents()
        collection = LocalCollection(documents)
        document_count = len(documents)
    repeats = 1 if args.live else REPEATS
    case_rows: list[dict] = []
    latencies: dict[str, list[float]] = defaultdict(list)
    confusion: dict[str, dict[str, int]] = {
        policy: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "retrieval_hit": 0}
        for policy in POLICIES
    }

    def run_cases() -> None:
        for case_index, (case_id, query, expected_id) in enumerate(CASES):
            # Warm code and connection, then time repeated retrieval against the
            # same result set for each policy to keep the comparison fair.
            if not args.live or case_index == 0:
                retrieve(query, settings.rag_top_k)
            policy_samples: dict[str, list[float]] = {policy: [] for policy in POLICIES}
            last_decisions = {}
            results = []
            for _ in range(repeats):
                started = time.perf_counter()
                results = retrieve(query, settings.rag_top_k)
                retrieval_ms = (time.perf_counter() - started) * 1000
                for policy in POLICIES:
                    gate_started = time.perf_counter()
                    last_decisions[policy] = evaluate(query, results, policy)
                    gate_ms = (time.perf_counter() - gate_started) * 1000
                    policy_samples[policy].append(retrieval_ms + gate_ms)

            for policy in POLICIES:
                last_decision = last_decisions[policy]
                latencies[policy].append(statistics.median(policy_samples[policy]))

                top_ids = [str(result.get("upstream_id", "")) for result in results]
                hit = bool(expected_id and expected_id in top_ids)
                accepted = bool(last_decision["sufficient"])
                matrix = confusion[policy]
                matrix["retrieval_hit"] += int(hit)
                if expected_id and accepted and hit:
                    matrix["tp"] += 1
                elif expected_id and accepted and not hit:
                    matrix["fp"] += 1
                elif expected_id and not accepted:
                    matrix["fn"] += 1
                elif not expected_id and accepted:
                    matrix["fp"] += 1
                else:
                    matrix["tn"] += 1

                # This is a mechanical gold-source citation check, not generated-answer correctness.
                citation_valid = False
                if accepted and expected_id and expected_id in top_ids:
                    citation_valid = True  # exact gold source is present in the offered source list
                case_rows.append({
                    "case_id": case_id,
                    "query": query,
                    "expected_upstream_id": expected_id or "",
                    "top5_upstream_ids": "|".join(top_ids),
                    "retrieval_hit_at_5": hit,
                    "policy": policy,
                    "accepted": accepted,
                    "relevance": round(last_decision["relevance"], 4),
                    "coverage": round(last_decision["coverage"], 4),
                    "latency_ms_median": round(statistics.median(policy_samples[policy]), 3),
                    "gold_source_citation_available": citation_valid,
                })

    if args.live:
        try:
            run_cases()
        finally:
            close_mongodb_connection()
    else:
        with patch("app.services.hybrid_retrieval.get_database", return_value={settings.knowledge_collection: collection}):
            run_cases()

    positive_count = sum(expected is not None for _, _, expected in CASES)
    negative_count = len(CASES) - positive_count
    summary = {
        "execution_mode": "live_mongodb" if args.live else "offline_processed_corpus",
        "corpus": settings.mongodb_database + "." + settings.knowledge_collection if args.live else str(CORPUS_PATH),
        "corpus_source_type": "attack-pattern",
        "corpus_documents": document_count,
        "cases": len(CASES),
        "answerable_cases": positive_count,
        "unanswerable_cases": negative_count,
        "top_k": settings.rag_top_k,
        "retrieval_runs_per_case": repeats,
        "policies": {},
        "limitations": [
            "Live run uses Atlas retrieval with model generation excluded." if args.live else
            "Offline replay of the processed corpus; live MongoDB Atlas DNS was unavailable.",
            "Unsupported answers and false abstentions are labelled by this small gold set.",
            "Citation metric is gold-source availability in the offered result list, not LLM citation validity or claim entailment.",
            "Latency is warm retrieval plus gate time; excludes model generation." if args.live else
            "Latency is warm local retrieval plus gate time; it excludes network, API generation, and MongoDB latency.",
        ],
    }
    for policy in POLICIES:
        matrix = confusion[policy]
        policy_rows = [row for row in case_rows if row["policy"] == policy]
        accepted_rows = [row for row in policy_rows if row["accepted"]]
        accepted_positive = [row for row in accepted_rows if row["expected_upstream_id"]]
        rejected_positive = [
            row for row in policy_rows
            if row["expected_upstream_id"] and not row["accepted"]
        ]
        unanswerable_accepted = [
            row for row in accepted_rows if not row["expected_upstream_id"]
        ]
        gate_false_abstentions = [
            row for row in rejected_positive if row["retrieval_hit_at_5"]
        ]
        unsupported_count = matrix["fp"]
        summary["policies"][policy] = {
            "unsupported_answers": unsupported_count,
            "unsupported_answer_rate_among_accepted": round(
                unsupported_count / len(accepted_rows), 4
            ) if accepted_rows else 0.0,
            "unanswerable_query_false_accept_rate": round(
                len(unanswerable_accepted) / negative_count, 4
            ) if negative_count else 0.0,
            "false_abstentions": matrix["fn"],
            "false_abstention_rate": round(matrix["fn"] / positive_count, 4) if positive_count else 0.0,
            "gate_false_abstentions_when_gold_was_retrieved": len(gate_false_abstentions),
            "supported_answer_rate": round(matrix["tp"] / positive_count, 4) if positive_count else 0.0,
            "answerable_retrieval_misses": sum(
                1 for row in policy_rows
                if row["expected_upstream_id"] and not row["retrieval_hit_at_5"]
            ),
            "retrieval_hit_at_5": round(matrix["retrieval_hit"] / positive_count, 4) if positive_count else 0.0,
            "gold_source_citation_available_rate_when_accepted": round(
                sum(row["gold_source_citation_available"] for row in accepted_positive)
                / len(accepted_positive), 4
            ) if accepted_positive else 0.0,
            "median_latency_ms": round(statistics.median(latencies[policy]), 3),
            "confusion_counts": matrix,
        }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "-live" if args.live else ""
    json_path = OUTPUT_DIR / f"evidence-policy-benchmark{suffix}.json"
    csv_path = OUTPUT_DIR / f"evidence-policy-benchmark-cases{suffix}.csv"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(case_rows[0]))
        writer.writeheader()
        writer.writerows(case_rows)
    print(json.dumps(summary, indent=2))
    print(f"\nSaved: {json_path}\nSaved: {csv_path}")


if __name__ == "__main__":
    main()
