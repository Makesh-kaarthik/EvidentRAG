from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from pathlib import Path
from statistics import mean
from typing import Any


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
DOCUMENTS_PATH = ROOT / "processed" / "index_documents.jsonl"
QUESTIONS_PATH = ROOT / "evaluation" / "retrieval_questions.jsonl"
RESULTS_PATH = ROOT / "evaluation" / "latest-results.json"

# Offline mode needs only ranking settings; --mongo reads the configured URI from the backend environment.
if "--mongo" not in sys.argv:
    os.environ.setdefault("MONGODB_URI", "mongodb://127.0.0.1:27017")
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import settings  # noqa: E402
from app.services.hybrid_retrieval import _bm25_scores  # noqa: E402
from app.services.text_index import _QUERY_SYNONYMS, term_frequencies  # noqa: E402


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def evaluate() -> dict[str, Any]:
    documents = _read_jsonl(DOCUMENTS_PATH)
    questions = _read_jsonl(QUESTIONS_PATH)
    manifest_path = ROOT / "processed" / "processing-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not documents:
        raise ValueError(f"No indexed documents found at {DOCUMENTS_PATH}")
    if not questions:
        raise ValueError(f"No evaluation questions found at {QUESTIONS_PATH}")

    for document in documents:
        if not isinstance(document.get("term_frequency"), dict):
            document["term_frequency"] = term_frequencies(document)
        document["token_count"] = int(
            document.get("token_count") or sum(document["term_frequency"].values())
        )

    known_ids = {str(document.get("upstream_id", "")).upper() for document in documents}
    results = []
    reciprocal_ranks = []
    hits_at_5 = []
    hits_at_1 = []

    for question in questions:
        query = question["query"]
        expected = {identifier.upper() for identifier in question["relevant_source_ids"]}
        missing = expected - known_ids
        if missing:
            raise ValueError(f"Unknown expected IDs for {question['id']}: {sorted(missing)}")

        scores = _bm25_scores(query, documents)
        ranked = [
            (document, score, exact_identifier)
            for document, (score, exact_identifier) in zip(documents, scores)
            if score > 0
        ]
        ranked.sort(key=lambda row: (row[2], row[1]), reverse=True)
        top_k = ranked[:5]
        reciprocal_rank = next(
            (1.0 / rank for rank, (doc, _, _) in enumerate(ranked, start=1)
             if str(doc.get("upstream_id", "")).upper() in expected),
            0.0,
        )
        hit_at_5 = any(str(doc.get("upstream_id", "")).upper() in expected for doc, _, _ in top_k)
        hit_at_1 = bool(ranked and str(ranked[0][0].get("upstream_id", "")).upper() in expected)
        reciprocal_ranks.append(reciprocal_rank)
        hits_at_5.append(float(hit_at_5))
        hits_at_1.append(float(hit_at_1))
        results.append({
            "id": question["id"],
            "query": query,
            "expected_ids": sorted(expected),
            "first_relevant_rank": (int(1 / reciprocal_rank) if reciprocal_rank else None),
            "reciprocal_rank": round(reciprocal_rank, 4),
            "hit_at_1": hit_at_1,
            "hit_at_5": hit_at_5,
            "top_5": [
                {
                    "upstream_id": doc.get("upstream_id"),
                    "title": doc.get("title"),
                    "source_type": doc.get("source_type"),
                    "score": round(score, 4),
                    "exact_identifier": exact,
                }
                for doc, score, exact in top_k
            ],
        })

    return {
        "document_count": len(documents),
        "question_count": len(questions),
        "corpus_sha256": manifest.get("output_sha256"),
        "corpus_generated_at_utc": manifest.get("generated_at_utc"),
        "metrics": {
            "recall_at_5": round(mean(hits_at_5), 4),
            "mean_reciprocal_rank": round(mean(reciprocal_ranks), 4),
            "top_1_accuracy": round(mean(hits_at_1), 4),
        },
        "results": results,
    }



def evaluate_mongo() -> dict[str, Any]:
    """Evaluate live retrieval through read-only MongoDB find/count operations."""
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    from app.services import hybrid_retrieval

    questions = _read_jsonl(QUESTIONS_PATH)
    client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=12000)
    try:
        client.admin.command("ping")
        database = client[settings.mongodb_database]
        collection = database[settings.knowledge_collection]
        # The production retrieval function reads through this database handle;
        # patching its getter avoids initializing app startup or writing state.
        hybrid_retrieval.get_database = lambda: database

        all_count = collection.count_documents({})
        text_count = collection.count_documents({"text": {"$exists": True}})
        local_index_count = collection.count_documents({"indexing_method": "bm25-local-v1"})
        known_ids = {
            str(value).upper()
            for value in collection.distinct("upstream_id", {"upstream_id": {"$exists": True}})
        }

        results = []
        reciprocal_ranks = []
        hits_at_5 = []
        hits_at_1 = []
        missing_expected = []
        for question in questions:
            expected = {identifier.upper() for identifier in question["relevant_source_ids"]}
            missing = sorted(expected - known_ids)
            if missing:
                missing_expected.append({"id": question["id"], "missing_source_ids": missing})
            ranked = hybrid_retrieval.retrieve(question["query"], settings.max_knowledge_chunks)
            reciprocal_rank = next(
                (1.0 / rank for rank, doc in enumerate(ranked, start=1)
                 if str(doc.get("upstream_id", "")).upper() in expected),
                0.0,
            )
            hit_at_5 = any(
                str(doc.get("upstream_id", "")).upper() in expected for doc in ranked[:5]
            )
            hit_at_1 = bool(
                ranked and str(ranked[0].get("upstream_id", "")).upper() in expected
            )
            reciprocal_ranks.append(reciprocal_rank)
            hits_at_5.append(float(hit_at_5))
            hits_at_1.append(float(hit_at_1))
            results.append({
                "id": question["id"],
                "expected_ids": sorted(expected),
                "first_relevant_rank": (int(1 / reciprocal_rank) if reciprocal_rank else None),
                "reciprocal_rank": round(reciprocal_rank, 4),
                "hit_at_1": hit_at_1,
                "hit_at_5": hit_at_5,
                "top_5": [
                    {
                        "upstream_id": doc.get("upstream_id"),
                        "title": doc.get("title"),
                        "source_type": doc.get("source_type"),
                        "score": round(float(doc.get("bm25_score", 0.0)), 4),
                        "exact_identifier": bool(doc.get("exact_identifier")),
                    }
                    for doc in ranked[:5]
                ],
            })

        offline = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        offline_by_id = {result["id"]: result for result in offline["results"]}
        live_by_id = {result["id"]: result for result in results}
        agreements = []
        for question_id, live_result in live_by_id.items():
            prior = offline_by_id.get(question_id)
            if prior is None:
                continue
            old_ids = [doc.get("upstream_id") for doc in prior["top_5"]]
            new_ids = [doc.get("upstream_id") for doc in live_result["top_5"]]
            union = set(old_ids) | set(new_ids)
            agreements.append({
                "id": question_id,
                "same_top_1": bool(old_ids and new_ids and old_ids[0] == new_ids[0]),
                "top_5_jaccard": round(len(set(old_ids) & set(new_ids)) / len(union), 4) if union else 1.0,
                "offline_first_relevant_rank": prior["first_relevant_rank"],
                "mongo_first_relevant_rank": live_result["first_relevant_rank"],
            })

        return {
            "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
            "read_only": True,
            "database": settings.mongodb_database,
            "collection": settings.knowledge_collection,
            "collection_counts": {
                "all_documents": all_count,
                "documents_with_text": text_count,
                "documents_marked_bm25_local": local_index_count,
            },
            "question_count": len(questions),
            "missing_expected_source_ids": missing_expected,
            "metrics": {
                "recall_at_5": round(mean(hits_at_5), 4),
                "mean_reciprocal_rank": round(mean(reciprocal_ranks), 4),
                "top_1_accuracy": round(mean(hits_at_1), 4),
            },
            "offline_metrics": offline["metrics"],
            "offline_vs_mongo": {
                "top_1_agreement": round(mean(float(item["same_top_1"]) for item in agreements), 4),
                "mean_top_5_jaccard": round(mean(item["top_5_jaccard"] for item in agreements), 4),
                "per_question": agreements,
            },
            "results": results,
        }
    except PyMongoError as error:
        raise RuntimeError(f"MongoDB evaluation failed ({type(error).__name__}); details were suppressed.") from None
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate local BM25 retrieval on held-out queries.")
    parser.add_argument("--mongo", action="store_true", help="Run a read-only retrieval comparison against MongoDB.")
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Use pre-title-boost scoring settings and the pre-expansion query vocabulary.",
    )
    args = parser.parse_args()
    if args.mongo and args.baseline:
        parser.error("--mongo and --baseline cannot be combined.")

    results_path = RESULTS_PATH
    if args.mongo:
        try:
            report = evaluate_mongo()
        except RuntimeError as error:
            raise SystemExit(str(error)) from None
        results_path = ROOT / "evaluation" / "mongo-results.json"
        results_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        metrics = report["metrics"]
        counts = report["collection_counts"]
        print(f"Collection: {report['database']}.{report['collection']}")
        print(f"Documents: {counts['all_documents']} total; {counts['documents_with_text']} with text; {counts['documents_marked_bm25_local']} BM25-local")
        print(f"Questions: {report['question_count']}")
        print(f"Recall@5: {metrics['recall_at_5']:.1%}")
        print(f"MRR: {metrics['mean_reciprocal_rank']:.3f}")
        print(f"Top-1 accuracy: {metrics['top_1_accuracy']:.1%}")
        agreement = report["offline_vs_mongo"]
        print(f"Offline/Mongo top-1 agreement: {agreement['top_1_agreement']:.1%}")
        print(f"Mean top-5 Jaccard: {agreement['mean_top_5_jaccard']:.3f}")
        print(f"Missing expected IDs in MongoDB: {len(report['missing_expected_source_ids'])}")
        print(f"Detailed report: {results_path}")
        return

    if args.baseline:
        settings.bm25_title_prefix_boost = 0.0
        settings.bm25_title_phrase_boost = 0.0
        settings.bm25_technique_over_tactic_boost = 0.0
        _QUERY_SYNONYMS.pop("attachments", None)
        _QUERY_SYNONYMS.pop("services", None)
        results_path = ROOT / "evaluation" / "expanded-baseline-results.json"

    report = evaluate()
    results_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    metrics = report["metrics"]
    print(f"Documents: {report['document_count']}")
    print(f"Questions: {report['question_count']}")
    print(f"Recall@5: {metrics['recall_at_5']:.1%}")
    print(f"MRR: {metrics['mean_reciprocal_rank']:.3f}")
    print(f"Top-1 accuracy: {metrics['top_1_accuracy']:.1%}")
    print(f"Detailed report: {results_path}")
    print("Per-question first relevant rank:")
    for result in report["results"]:
        rank = result["first_relevant_rank"]
        print(f"  {result['id']}: {('not found' if rank is None else f'rank {rank}')} | expected {', '.join(result['expected_ids'])}")


if __name__ == "__main__":
    main()
