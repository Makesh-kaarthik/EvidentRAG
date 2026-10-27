"""Evidence-grounded API query flow using local indexing and Gemini generation."""

import asyncio
import re

from fastapi import HTTPException
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.models.schemas import PipelineStatus, QueryRequest, QueryResponse, Source
from app.services.citation_validation import validate_citations
from app.services.evidence_intelligence import evaluate
from app.services.gemini_client import generate_grounded_answer
from app.services.hybrid_retrieval import retrieve
from app.services.model_catalog import default_model_id, get_model
from app.services.openrouter_client import generate_grounded_answer as generate_openrouter_answer
from app.services.prompt_optimizer import optimize_prompt


_NO_EVIDENCE = (
    "I couldn't find enough supporting evidence in the indexed cybersecurity "
    "knowledge base to answer this safely. Try a narrower question or add a "
    "relevant source to the knowledge base."
)


def _make_sources(results: list[dict]) -> list[Source]:
    return [
        Source(
            title=result.get("title", "Untitled source"),
            source=result.get("source", "Unknown"),
            score=round(float(result.get("relevance", 0.0)), 4),
            url=result.get("url"),
            citation_id=f"E{index}",
        )
        for index, result in enumerate(results, start=1)
    ]


def _direct_evidence_answer(
    query: str,
    results: list[dict],
    evidence_by_label: dict[str, str],
) -> str | None:
    """Answer simple lookup questions from retrieved evidence without a model call."""
    normalized = query.strip().casefold()
    if (
        len(normalized.split()) > 14
        or any(term in normalized for term in ("compare", "list all", "examples", "why", "how", "steps", "difference"))
        or not normalized.startswith(("what", "which", "who", "where", "define", "explain", "name", "identify"))
    ):
        return None
    if not results:
        return None

    result = results[0]
    label = "E1"
    title = str(result.get("title", "Relevant evidence"))
    text = str(result.get("text", ""))
    description = re.search(r"Description:\s*(.*?)(?:\n|$)", text, re.IGNORECASE)
    detail = description.group(1).strip() if description else text.strip()
    detail = re.split(r"(?<=[.!?])\s+(?=[A-Z])", detail, maxsplit=1)[0].strip().rstrip(" .")

    if normalized.startswith(("what is", "define", "explain")):
        answer = f"{title}: {detail} [{label}]." if detail else f"{title} [{label}]."
    else:
        category = {
            "attack-pattern": "ATT&CK technique",
            "course-of-action": "mitigation",
        }.get(result.get("source_type"), "matching source")
        answer = f"The best-matching {category} is {title} [{label}]."
        if detail:
            answer += f" {detail} [{label}]."

    if validate_citations(
        answer,
        evidence_by_label,
        minimum_token_overlap=settings.citation_min_token_overlap,
    ):
        return answer
    return None


async def process_query(request: QueryRequest) -> QueryResponse:
    query = request.query.strip()
    try:
        results = await asyncio.to_thread(retrieve, query, settings.rag_top_k)
    except (PyMongoError, RuntimeError) as error:
        raise HTTPException(
            status_code=503,
            detail="The knowledge database is temporarily unavailable.",
        ) from error
    assessment = evaluate(query, results)
    sources = _make_sources(results)
    pipeline = PipelineStatus(
        query_processing="Complete",
        hybrid_retrieval="Complete (local BM25)" if results else "No indexed evidence",
        cross_encoder_reranking=(
            f"Local BM25 + evidence reranker ({settings.retrieval_candidate_limit} candidates)"
            if results else "Skipped (no candidates)"
        ),
        prompt_optimization="Skipped (insufficient evidence)"
        if not assessment["sufficient"]
        else "Pending",
        evidence_verification="Sufficient" if assessment["sufficient"] else "Insufficient",
        response_generation="Skipped" if not assessment["sufficient"] else "Pending",
    )

    metrics = {
        "confidence": round(assessment["confidence"] * 100, 1),
        "coverage": round(assessment["coverage"] * 100, 1),
        "relevance": round(assessment["relevance"] * 100, 1),
    }
    if not assessment["sufficient"]:
        return QueryResponse(
            query=query,
            answer=_NO_EVIDENCE,
            **metrics,
            sources=sources,
            pipeline=pipeline,
            sufficient=False,
            abstained=True,
        )

    prompt = optimize_prompt(
        query,
        results,
        max_context_chars=settings.prompt_context_max_chars,
    )
    # Keep the evidence panel and citation validator aligned with the context
    # that actually reached the model.
    included_count = len(prompt.citation_ids)
    sources = _make_sources(results[:included_count])
    pipeline.prompt_optimization = (
        f"Complete ({prompt.intent}; {prompt.context_characters} context characters)"
    )

    direct_answer = _direct_evidence_answer(
        query, results[:included_count], dict(prompt.evidence_by_label)
    )
    if direct_answer:
        pipeline.response_generation = "Complete (direct evidence answer)"
        return QueryResponse(
            query=query,
            answer=direct_answer,
            **metrics,
            sources=sources,
            pipeline=pipeline,
            sufficient=True,
            abstained=False,
        )

    selected_model = get_model(request.model or default_model_id())

    try:
        if selected_model["provider"] == "OpenRouter":
            answer = await generate_openrouter_answer(
                prompt.user_prompt,
                system_instruction=prompt.system_instruction,
                model=selected_model["model_id"],
            )
        else:
            answer = await generate_grounded_answer(
                prompt.user_prompt,
                system_instruction=prompt.system_instruction,
                model=selected_model["model_id"],
            )
    except RuntimeError as error:
        raise HTTPException(
            status_code=502,
            detail="The answer generation service is temporarily unavailable.",
        ) from error
    citations_valid = validate_citations(
        answer, dict(prompt.evidence_by_label),
        minimum_token_overlap=settings.citation_min_token_overlap,
    )
    if not citations_valid:
        repair_prompt = (
            f"{prompt.user_prompt}\n\n"
            "Rewrite as a concise answer. Every sentence must end with one or more exact "
            "citation labels from the evidence (for example, [E1]). Do not add uncited "
            "introductions, headings, or limitations. Only include claims and identifiers "
            "directly supported by their cited evidence."
        )
        try:
            if selected_model["provider"] == "OpenRouter":
                answer = await generate_openrouter_answer(
                    repair_prompt,
                    system_instruction=prompt.system_instruction,
                    model=selected_model["model_id"],
                )
            else:
                answer = await generate_grounded_answer(
                    repair_prompt,
                    system_instruction=prompt.system_instruction,
                    model=selected_model["model_id"],
                )
        except RuntimeError as error:
            raise HTTPException(
                status_code=502,
                detail="The answer generation service is temporarily unavailable.",
            ) from error
        citations_valid = validate_citations(
            answer, dict(prompt.evidence_by_label),
            minimum_token_overlap=settings.citation_min_token_overlap,
        )

    if not citations_valid:
        answer = (
            "I found relevant material, but couldn't verify the answer's citations. "
            "I won't present it as a grounded answer."
        )
        abstained = True
        pipeline.response_generation = "Citation validation failed"
    else:
        abstained = False
        pipeline.response_generation = "Complete"

    return QueryResponse(
        query=query,
        answer=answer,
        **metrics,
        sources=sources,
        pipeline=pipeline,
        sufficient=True,
        abstained=abstained,
        model=selected_model["name"] if not abstained else None,
    )
