"""Compare evidence-gate policies on labeled in-corpus and out-of-corpus queries.

Run from Application/backend with the bundled Python runtime. This is a local,
deterministic gate benchmark; it does not call MongoDB or an answer model.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path
from time import perf_counter_ns
from typing import Any


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import settings  # noqa: E402
from app.services.evidence_intelligence import evaluate as assess_evidence  # noqa: E402
from app.services.hybrid_retrieval import _bm25_scores  # noqa: E402
from app.services.text_index import term_frequencies  # noqa: E402


EVALUATION_DIR = ROOT / "evaluation"
POLICIES = ("no_gate", "relevance_only", "coverage_only", "current")
LATENCY_REPETITIONS = 500


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _load_cases() -> list[dict[str, Any]]:
    answerable = []
    for item in _read_jsonl(EVALUATION_DIR / "retrieval_questions.jsonl"):
        answerable.append({
            "id": item["id"],
            "query": item["query"],
            "answerable": True,
            "expected_ids": [value.upper() for value in item["relevant_source_ids"]],
        })
    unanswerable = _read_jsonl(EVALUATION_DIR / "evidence_gate_unanswerable.jsonl")
    return answerable + unanswerable


def _load_documents() -> list[dict[str, Any]]:
    path = ROOT / "processed" / "index_documents.jsonl"
    documents = _read_jsonl(path)
    for document in documents:
        document["term_frequency"] = term_frequencies(document)
        document["token_count"] = sum(document["term_frequency"].values())
        document["_tokens"] = set(document["term_frequency"])
    return documents


def _rank(query: str, documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = _bm25_scores(query, documents)
    results = []
    for source, (raw_score, exact_identifier) in zip(documents, scored):
        if raw_score <= 0:
            continue
        result = dict(source)
        result["exact_identifier"] = exact_identifier
        result["relevance"] = raw_score / (raw_score + settings.bm25_score_saturation)
        result["bm25_score"] = raw_score
        results.append(result)
    results.sort(key=lambda item: (item["exact_identifier"], item["bm25_score"]), reverse=True)
    return results[: settings.rag_top_k]


def evaluate() -> dict[str, Any]:
    cases = _load_cases()
    documents = _load_documents()
    if not cases or not documents:
        raise ValueError("Evaluation needs labeled queries and a processed corpus.")

    rows: dict[str, list[dict[str, Any]]] = {policy: [] for policy in POLICIES}
    for case in cases:
        results = _rank(case["query"], documents)
        expected = set(case.get("expected_ids", []))
        retrieved_expected = any(
            str(item.get("upstream_id", "")).upper() in expected for item in results
        )
        for policy in POLICIES:
            started = perf_counter_ns()
            for _ in range(LATENCY_REPETITIONS):
                assessment = assess_evidence(case["query"], results, policy=policy)
            elapsed_ms = (perf_counter_ns() - started) / 1_000_000 / LATENCY_REPETITIONS
            rows[policy].append({
                "id": case["id"],
                "answerable": case["answerable"],
                "accepted": assessment["sufficient"],
                "relevance": assessment["relevance"],
                "coverage": assessment["coverage"],
                "exact_identifier": bool(results and results[0].get("exact_identifier")),
                "retrieved_expected_in_top_k": retrieved_expected if case["answerable"] else None,
                "gate_latency_ms": elapsed_ms,
            })

    summaries = {}
    for policy, policy_rows in rows.items():
        positives = [row for row in policy_rows if row["answerable"]]
        negatives = [row for row in policy_rows if not row["answerable"]]
        latencies = [row["gate_latency_ms"] for row in policy_rows]
        summaries[policy] = {
            "answerable_queries": len(positives),
            "unanswerable_queries": len(negatives),
            "answerable_accept_rate": sum(row["accepted"] for row in positives) / len(positives),
            "false_abstention_rate": sum(not row["accepted"] for row in positives) / len(positives),
            "unanswerable_accept_rate": sum(row["accepted"] for row in negatives) / len(negatives),
            "potential_unsupported_generation_rate": sum(row["accepted"] for row in negatives) / len(negatives),
            "overall_abstention_rate": sum(not row["accepted"] for row in policy_rows) / len(policy_rows),
            "mean_gate_latency_ms": statistics.mean(latencies),
            "median_gate_latency_ms": statistics.median(latencies),
        }

    return {
        "evaluation": "deterministic evidence-gate policy comparison",
        "generated_at_note": "Run timestamp intentionally omitted for reproducible content.",
        "corpus_document_count": len(documents),
        "query_count": len(cases),
        "answerable_query_count": sum(bool(case["answerable"]) for case in cases),
        "unanswerable_query_count": sum(not case["answerable"] for case in cases),
        "gate_thresholds": {
            "minimum_relevance": settings.evidence_min_local_relevance,
            "minimum_query_coverage": settings.evidence_min_query_coverage,
            "current_confidence_weights": {"coverage": 0.65, "relevance": 0.35},
            "top_k": settings.rag_top_k,
        },
        "policies": summaries,
        "citation_validity": {
            "status": "not_measured",
            "reason": "This benchmark does not generate answers or contain human-labeled answer/citation judgments.",
        },
        "latency_scope": "Evidence gate evaluation only; excludes retrieval, model generation, and citation validation.",
        "latency_repetitions_per_case_and_policy": LATENCY_REPETITIONS,
        "limitations": [
            "The unanswerable controls are a small, hand-authored out-of-corpus set and require domain review.",
            "Answerable labels come from the existing retrieval benchmark; gate acceptance does not establish answer correctness.",
            "Potential unsupported generation rate is the fraction of out-of-corpus cases the gate would pass, not an observed answer error rate.",
            "Gate latency is a local microbenchmark and varies by machine and runtime load.",
        ],
        "cases": rows,
    }


if __name__ == "__main__":
    report = evaluate()
    output = EVALUATION_DIR / "evidence-gate-results.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    print(f"Corpus: {report['corpus_document_count']} documents; queries: {report['query_count']}")
    for policy, metrics in report["policies"].items():
        print(
            f"{policy:16} answerable_accept={metrics['answerable_accept_rate']:.1%} "
            f"false_abstention={metrics['false_abstention_rate']:.1%} "
            f"unanswerable_accept={metrics['unanswerable_accept_rate']:.1%} "
            f"mean_gate_ms={metrics['mean_gate_latency_ms']:.4f}"
        )
    print("Citation validity: not measured (no generated-answer judgments in this benchmark).")
