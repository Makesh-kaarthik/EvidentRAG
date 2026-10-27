"""Local BM25 retrieval with identifier and cybersecurity synonym boosts."""

import math
import re
from collections import Counter

from app.core.config import settings
from app.core.database import get_database
from app.services.text_index import (
    extract_identifiers, query_expansion_terms, query_phrase_tokens, query_terms, term_frequencies, tokenize,
)


def _bm25_scores(query: str, records: list[dict]) -> list[tuple[float, bool]]:
    terms = list(dict.fromkeys((*query_terms(query), *query_expansion_terms(query))))
    if not terms or not records:
        return [(0.0, False) for _ in records]

    frequencies = []
    lengths = []
    for record in records:
        term_freq = record.get("term_frequency")
        if not isinstance(term_freq, dict):
            term_freq = term_frequencies(record)
        frequencies.append(term_freq)
        lengths.append(int(record.get("token_count") or sum(term_freq.values())))

    count = len(records)
    average_length = sum(lengths) / count or 1.0
    document_frequency = Counter(
        term for term in set(terms) for document in frequencies if document.get(term, 0) > 0
    )
    k1 = settings.bm25_k1
    b = settings.bm25_b
    identifiers = extract_identifiers(query)
    phrase_terms = query_phrase_tokens(query)
    asks_for_technique = "technique" in terms
    scored = []

    for record, term_freq, length in zip(records, frequencies, lengths):
        score = 0.0
        for term in terms:
            term_count = term_freq.get(term, 0)
            if not term_count:
                continue
            df = document_frequency[term]
            inverse_frequency = math.log(1 + (count - df + 0.5) / (df + 0.5))
            denominator = term_count + k1 * (1 - b + b * length / average_length)
            score += inverse_frequency * term_count * (k1 + 1) / denominator

        if "attack-pattern" in terms and record.get("source_type") == "attack-pattern":
            score += settings.bm25_technique_over_tactic_boost

        upstream_id = str(record.get("upstream_id", "")).upper()
        exact_identifier = bool(identifiers and any(identifier == upstream_id for identifier in identifiers))
        if exact_identifier:
            score += settings.bm25_identifier_boost

        # Give the named concept in a source title a bounded boost. A phrase at
        # the start of the title is a stronger match than one embedded in a
        # longer title, such as “Remote Services” vs “Exploitation of Remote
        # Services”.
        title_terms = query_phrase_tokens(str(record.get("title", "")))
        title_boost = 0.0
        for index in range(len(phrase_terms) - 1):
            phrase = phrase_terms[index:index + 2]
            positions = [
                title_index
                for title_index in range(len(title_terms) - 1)
                if title_terms[title_index:title_index + 2] == phrase
            ]
            if positions:
                boost = (
                    settings.bm25_title_prefix_boost
                    if positions[0] == 0
                    else settings.bm25_title_phrase_boost
                )
                title_boost = max(title_boost, boost)
        score += title_boost

        if asks_for_technique and record.get("source_type") == "x-mitre-tactic":
            score -= settings.bm25_technique_over_tactic_boost
        scored.append((score, exact_identifier))
    return scored


def retrieve(query: str, limit: int) -> list[dict]:
    collection = get_database()[settings.knowledge_collection]
    technique_query = bool(re.search(r"\b(?:sub[ -]?technique|technique|att&ck)\b", query, re.IGNORECASE))
    mitigation_query = bool(
        re.search(r"\b(?:mitigat\w*|countermeasure\w*)\b", query, re.IGNORECASE)
        or re.search(
            r"^\s*(?:how|what|which)\b.{0,100}\b(?:protect\w*|prevent\w*|defend\w*|secure\w*|safeguard\w*)\b",
            query,
            re.IGNORECASE,
        )
    )
    kev_query = bool(re.search(r"\b(?:kev|known exploited vulnerabilities)\b", query, re.IGNORECASE))
    vulnerability_query = bool(
        extract_identifiers(query)
        or re.search(r"\b(?:vulnerabilit\w*|cve|affected version|patch)\b", query, re.IGNORECASE)
    )
    tactic_query = bool(re.search(r"\btactic\b", query, re.IGNORECASE))
    if mitigation_query:
        source_scope = {"source_type": "course-of-action"}
    elif kev_query:
        source_scope = {"source_type": "cisa-kev"}
    elif vulnerability_query:
        source_scope = {"source_type": {"$in": ["nvd-cve", "cisa-kev"]}}
    elif tactic_query and not technique_query:
        source_scope = {"source_type": "x-mitre-tactic"}
    else:
        # Natural-language attack descriptions often omit the words
        # “ATT&CK” and “technique”; behavior questions still belong to this corpus.
        source_scope = {"source_type": "attack-pattern"}
    candidate_terms = list(dict.fromkeys((*query_terms(query), *query_expansion_terms(query))))
    literal_terms = list(dict.fromkeys(tokenize(query)))
    anchor_terms = set((*query_phrase_tokens(query), *query_terms(query)))
    if technique_query:
        anchor_terms.difference_update({"attack-pattern", "technique", "sub-technique", "execute", "execution", "command", "commands"})
    if mitigation_query:
        anchor_terms.difference_update({"mitigation", "mitigations", "mitigate", "protect", "protection", "defend", "prevent", "theft", "steal"})
    if not anchor_terms:
        anchor_terms = set(literal_terms)
    identifiers = extract_identifiers(query)
    clauses = [
        {f"term_frequency.{term}": {"$exists": True}}
        for term in candidate_terms
        if re.fullmatch(r"[a-z0-9_-]+", term)
    ]
    if identifiers:
        clauses.append({"upstream_id": {"$in": identifiers}})
    if not clauses:
        return []
    projection = {
        "_id": 0,
        "chunk_id": 1,
        "source_id": 1,
        "upstream_id": 1,
        "source_type": 1,
        "source_version": 1,
        "title": 1,
        "source": 1,
        "url": 1,
        "text": 1,
        "term_frequency": 1,
        "token_count": 1,
    }
    # Keep both Mongo transfer and Python reranking bounded for each query.
    candidate_limit = min(settings.retrieval_candidate_limit, max(limit * 6, 24))
    base_filter = {"text": {"$exists": True}}
    # Query specific anchors first so broad terms cannot consume the candidate
    # budget. Each indexed lookup is capped; the bounded pool is reranked with
    # the full BM25/semantic score below. This avoids expensive server-side
    # computed sorts over the entire ATT&CK collection.
    generic_terms = {
        "adversary", "adversaries", "attacker", "attackers", "operator", "operators",
        "malware", "windows", "system", "security", "account", "accounts", "access",
        "network", "remote", "host", "machine", "commands", "command", "payload",
        "user", "file", "files", "information", "data", "service",
    }
    distinctive_terms = {
        "lsass", "powershell", "rdp", "smb", "vnc", "ssh", "winrm", "wevtutil",
        "systeminfo", "mimikatz", "kerberos", "schtasks", "backdoor", "mfa", "7-zip",
        "spearphishing", "rundll32", "regsvr32", "wmic", "wmiprvse", "mshta",
    }
    ranked_terms = sorted(
        (term for term in literal_terms if re.fullmatch(r"[a-z0-9_-]+", term)),
        key=lambda term: (term in distinctive_terms, term not in generic_terms, len(term)),
        reverse=True,
    )
    # Include several distinct behavior anchors (e.g. LSASS, PowerShell, and
    # Remote Desktop) so a long incident description can retrieve evidence for
    # each stage instead of only its first clause.
    semantic_anchors = sorted(
        (term for term in candidate_terms if term not in literal_terms),
        key=lambda term: (
            term in distinctive_terms,
            term not in generic_terms,
            len(term),
        ),
        reverse=True,
    )[:3]
    anchor_terms = list(dict.fromkeys([
        *identifiers,
        *ranked_terms[:3],
        *semantic_anchors,
    ]))
    fetched = {}
    anchor_quota = max(1, candidate_limit // max(len(anchor_terms), 1))
    for term in anchor_terms:
        if term in identifiers:
            term_filter = {"upstream_id": term}
        else:
            term_filter = {f"term_frequency.{term}": {"$exists": True}}
        query_filter = {**base_filter, **source_scope, **term_filter}
        cursor = collection.find(query_filter, projection)
        # A common anchor such as PowerShell can match many techniques. Rank
        # that small slice by the other query concepts before applying its
        # quota, so the exact behavior match is not lost to natural DB order.
        secondary_terms = sorted(
            (
                candidate for candidate in candidate_terms
                if candidate != term and re.fullmatch(r"[a-z0-9_-]+", candidate)
            ),
            key=lambda candidate: (
                candidate in distinctive_terms,
                candidate not in generic_terms,
                len(candidate),
            ),
            reverse=True,
        )[:5]
        if secondary_terms and hasattr(cursor, "sort"):
            cursor = cursor.sort(
                [(f"term_frequency.{candidate}", -1) for candidate in secondary_terms]
            )
        for record in cursor.limit(anchor_quota):
            key = record.get("chunk_id") or record.get("source_id") or record.get("upstream_id")
            if key is not None and key not in fetched:
                fetched[key] = record
            if len(fetched) >= candidate_limit:
                break
        if len(fetched) >= candidate_limit:
            break
    if len(fetched) < candidate_limit:
        for record in collection.find(
            {**base_filter, **source_scope, "$or": clauses}, projection
        ).limit(candidate_limit - len(fetched)):
            key = record.get("chunk_id") or record.get("source_id") or record.get("upstream_id")
            if key is not None:
                fetched[key] = record
    records = list(fetched.values())
    if not records:
        return []

    scored = _bm25_scores(query, records)
    title_terms_by_record = [
        set(query_terms(str(record.get("title", "")))) for record in records
    ]
    title_document_frequency = Counter(
        term
        for term in candidate_terms
        for title_terms in title_terms_by_record
        if term in title_terms
    )
    for record, (raw_score, exact_identifier), title_terms in zip(records, scored, title_terms_by_record):
        if not isinstance(record.get("term_frequency"), dict):
            record["term_frequency"] = term_frequencies(record)
        record["_tokens"] = set(record["term_frequency"])
        record["bm25_score"] = raw_score
        record["exact_identifier"] = exact_identifier
        record["relevance"] = raw_score / (raw_score + settings.bm25_score_saturation) if raw_score > 0 else 0.0
        base_terms = list(dict.fromkeys(query_terms(query)))
        semantic_terms = list(dict.fromkeys(query_expansion_terms(query)))
        coverage = sum(1 for term in base_terms if record["term_frequency"].get(term, 0)) / max(len(base_terms), 1)
        semantic_match = sum(1 for term in semantic_terms if record["term_frequency"].get(term, 0)) / max(len(semantic_terms), 1)
        title_match = sum(1 for term in base_terms if term in title_terms) / max(len(base_terms), 1)
        semantic_title_weight = sum(
            math.log(1 + (len(records) + 0.5) / (title_document_frequency[term] + 0.5))
            for term in candidate_terms if term in title_terms
        )
        total_title_weight = sum(
            math.log(1 + (len(records) + 0.5) / (title_document_frequency[term] + 0.5))
            for term in candidate_terms
        ) or 1.0
        title_semantic_match = semantic_title_weight / total_title_weight
        anchor_title_match = sum(term in title_terms for term in anchor_terms) / max(len(anchor_terms), 1)
        record["anchor_title_match"] = anchor_title_match
        record["rerank_score"] = (
            0.30 * record["relevance"]
            + 0.15 * coverage
            + 0.15 * semantic_match
            + 0.08 * title_match
            + 0.10 * title_semantic_match
            + 0.40 * anchor_title_match
            + (0.5 if exact_identifier else 0.0)
        )

    relevant = [record for record in records if record["bm25_score"] > 0]
    return sorted(
        relevant,
        key=lambda item: (
            item["exact_identifier"],
            item["rerank_score"],
            item["bm25_score"],
        ),
        reverse=True,
    )[:limit]
