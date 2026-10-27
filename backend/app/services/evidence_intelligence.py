"""Evidence sufficiency gate driven by local BM25 scores and term coverage."""

from app.core.config import settings
from app.services.text_index import query_terms


def evaluate(query: str, results: list[dict], policy: str = "current") -> dict:
    """Assess evidence and apply a selectable policy for offline comparisons.

    Supported policies: ``current`` (relevance AND coverage, with exact-ID
    override), ``no_gate``, ``relevance_only``, and ``coverage_only``.
    The score remains a heuristic and is not a probability of correctness.
    """
    if policy not in {"current", "no_gate", "relevance_only", "coverage_only"}:
        raise ValueError(f"Unknown evidence policy: {policy}")
    query_tokens = set(query_terms(query))
    if not results or not query_tokens:
        sufficient = policy == "no_gate"
        return {
            "sufficient": sufficient,
            "relevance": 0.0,
            "coverage": 0.0,
            "confidence": 0.0,
        }

    evidence_tokens = set()
    for result in results[:3]:
        evidence_tokens.update(result.get("_tokens", []))
    coverage = len(query_tokens & evidence_tokens) / len(query_tokens)
    relevance = max(0.0, min(1.0, float(results[0].get("relevance", 0.0))))
    exact_identifier = bool(results[0].get("exact_identifier"))
    relevance_passes = relevance >= settings.evidence_min_local_relevance
    coverage_passes = coverage >= settings.evidence_min_query_coverage
    sufficient = {
        "current": exact_identifier or (relevance_passes and coverage_passes),
        "no_gate": True,
        "relevance_only": relevance_passes,
        "coverage_only": coverage_passes,
    }[policy]

    # This score is a local heuristic, not a calibrated probability.
    confidence = 0.65 * coverage + 0.35 * relevance
    return {
        "sufficient": sufficient,
        "relevance": relevance,
        "coverage": max(0.0, min(1.0, coverage)),
        "confidence": max(0.0, min(1.0, confidence)),
    }
