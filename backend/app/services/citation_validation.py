"""Conservative, deterministic checks for answer citations and source overlap."""

import re
from collections.abc import Mapping

from app.services.text_index import extract_identifiers, query_phrase_tokens

_CITATION_PATTERN = re.compile(r"\[(E\d+)\]")
_NUMBER_PATTERN = re.compile(r"\b\d+(?:\.\d+)?%?\b")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def _is_heading(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.startswith("**") and stripped.endswith("**") and len(query_phrase_tokens(stripped)) <= 8:
        return True
    if stripped.startswith("#") and len(query_phrase_tokens(stripped)) <= 8:
        return True
    return False


def validate_citations(
    answer: str,
    evidence_by_label: Mapping[str, str],
    *,
    minimum_token_overlap: float = 0.30,
) -> bool:
    """Require each claim to cite supplied evidence with identifiers/numbers supported.

    Token overlap is a conservative lexical signal, not semantic entailment.
    """
    if not answer or not evidence_by_label:
        return False

    saw_claim = False
    for sentence in _SENTENCE_SPLIT.split(answer.strip()):
        if _is_heading(sentence):
            continue
        labels = _CITATION_PATTERN.findall(sentence)
        if not labels or any(label not in evidence_by_label for label in labels):
            return False

        claim = _CITATION_PATTERN.sub("", sentence)
        claim = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", "", claim).strip(" \t.,;:")
        claim_terms = set(query_phrase_tokens(claim))
        if not claim_terms:
            return False
        saw_claim = True

        cited_evidence = [evidence_by_label[label] for label in dict.fromkeys(labels)]
        evidence_terms_by_label = [set(query_phrase_tokens(source)) for source in cited_evidence]
        # Every cited source must overlap the claim; one relevant citation must
        # not make an unrelated extra citation appear valid.
        if any(not claim_terms.intersection(source_terms) for source_terms in evidence_terms_by_label):
            return False
        combined_terms = set().union(*evidence_terms_by_label)
        overlap = len(claim_terms & combined_terms) / len(claim_terms)
        if overlap < minimum_token_overlap:
            return False

        claim_ids = set(extract_identifiers(claim))
        evidence_ids = set().union(*(set(extract_identifiers(source)) for source in cited_evidence))
        if not claim_ids.issubset(evidence_ids):
            return False

        claim_numbers = set(_NUMBER_PATTERN.findall(claim))
        evidence_numbers = set(_NUMBER_PATTERN.findall(" ".join(cited_evidence)))
        if not claim_numbers.issubset(evidence_numbers):
            return False

    return saw_claim
