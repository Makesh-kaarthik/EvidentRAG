# Updated project idea: local evidence indexing and prompt optimization

## Goal

Cyber EvidentRAG should build and search its own traceable cybersecurity source index. LLM calls belong in answer generation, after retrieval and evidence checks. Dataset ingestion, tokenization, ranking, and prompt construction should be deterministic local Python code.

## Data flow

1. **Acquire** versioned first-party sources into `Datasets/raw/`; preserve each source's license, URL, retrieval time, and checksum.
2. **Normalize** supported source objects into small JSONL documents with stable IDs, titles, source type, source version, URL, and canonical text.
3. **Index locally** by tokenizing title, source, upstream ID, and text; store term frequencies and token count in MongoDB. Use stable source IDs for idempotent upserts. This stage does not contact Gemini or create embeddings.
4. **Retrieve locally** with BM25, a limited cybersecurity synonym map, and exact CVE/ATT&CK identifier boosts. Apply the evidence coverage gate before generation.
5. **Optimize the prompt locally** by identifying the question's response focus, selecting only top evidence, assigning `[E1]` style labels, clipping context to a configured budget, and keeping system instructions separate from untrusted source text.
6. **Generate and validate** with the configured LLM. Ask it to use only supplied evidence and cite each factual sentence. Validate every sentence against the exact excerpts sent to the model; reject uncited claims, unknown labels, unsupported CVE/ATT&CK IDs or numbers, and claims with too little lexical overlap with their cited sources. This overlap check is a heuristic and does not prove semantic entailment.

## Prompt optimizer responsibilities

The prompt optimizer is a deterministic Python component, not another model call. It should:

- Choose a useful answer focus for definitions, ATT&CK techniques, vulnerabilities, and defensive guidance.
- Keep the user question intact and include a bounded number of ranked sources.
- Preserve source title, URL, and citation label alongside the excerpt.
- Treat source text as data that may contain hostile instructions.
- Report which source labels were included so citation validation and the UI match the actual model context.

## Current implementation scope

- Sources: active MITRE ATT&CK techniques, mitigations and tactics; all records from the downloaded CISA KEV catalog; the small curated starter corpus.
- Local index: MongoDB records with normalized term-frequency maps, token counts, content hashes, version, and provenance.
- Retrieval: local BM25 with acronym expansion and exact identifier boosts; no vector fields are needed.
- Generation: Gemini or OpenRouter text models after the evidence gate passes; provider keys remain in the backend environment. Current OpenRouter dropdown choices use free Nemotron text endpoints.
- Dataset processing: `Datasets/prepare_index_documents.py`.
- MongoDB local indexing: `backend/app/scripts/index_sources.py`.
- Prompt construction: `backend/app/services/prompt_optimizer.py`.

## Limits and next improvements

This lexical retriever may miss semantically related questions whose vocabulary differs from source wording. Its synonym map and evidence thresholds need evaluation with a labeled question set. The current prototype scans at most 5,000 indexed records in application code; a proper inverted index or database search index is the next scale step. NVD and CISA advisory parsers are not yet included. Confidence and relevance values are heuristic signals, not probabilities.
