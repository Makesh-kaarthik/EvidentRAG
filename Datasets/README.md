# Cyber EvidentRAG datasets

This folder separates machine-readable source data from the backend and frontend. Keep the original download, source URL, retrieval date, version, checksum, and terms together. Treat imported content as untrusted data; never execute files from a dataset.

## Folder layout

- `curated/mitre_starter.json` — four small, source-linked summaries used by the current RAG seed loader.
- `raw/` — original downloads, retained unchanged. It contains MITRE ATT&CK, CISA KEV, and supported NVD yearly CVE feeds (ZIP plus extracted JSON). Raw files are ignored by Git.
- `licenses/` — the MITRE ATT&CK license text and CISA KEV CC0 license text.
- `catalog.json` — source registry with intended use, acquisition URL, refresh guidance, rights notes, and current local status.
- `acquisition-manifest.json` — retrieval timestamp, record counts, sizes, source URLs, and SHA-256 checksums for the downloaded files.
- `processed/index_documents.jsonl` — normalized, source-linked retrieval records generated from ATT&CK techniques/mitigations/tactics and CISA KEV.

## Recommended acquisition order

1. **MITRE ATT&CK Enterprise STIX 2.1** for technique descriptions, tactics, mitigations, and references. Use the versioned bundle in the catalog so a rebuild uses a known release. MITRE permits research, development, and commercial use at no charge under its ATT&CK license; preserve its copyright notice and license with copies, and do not imply MITRE endorsement.
2. **CISA Known Exploited Vulnerabilities (KEV)** for a compact, regularly updated set of vulnerabilities confirmed exploited in the wild. Keep CVE IDs, descriptions, dates, required actions, and the source URL. CISA's data license permits legal reuse; linked third-party content retains its own terms.
3. **NVD CVE API 2.0** for vulnerability descriptions, CVSS metrics, weaknesses, and affected-product configuration data. Query by CVE or date window and follow NVD's pagination and rate limits. Preserve per-record references and check NVD terms plus rights for third-party content.
4. **CWE and CAPEC** for standardized weakness and attack-pattern definitions. These are useful for linking vulnerability records to causes and exploitation patterns; retain the upstream identifiers and attribution.
5. **CISA advisories** for operational mitigations and incident context. Prefer the original advisory pages and their linked files; record each advisory's publication/update date.

## Refresh the downloaded first-party sources

From PowerShell in this folder, run:

```powershell
..\backend\python313\python.exe .\acquire_sources.py --source all
```

Choose `--source cisa-kev`, `--source mitre-enterprise`, or `--source nvd-2026` to refresh one source. For NVD, the downloader checks the official `.meta` size and SHA-256, verifies ZIP integrity, extracts the JSON, and records provenance. It downloads source data only; it does not send data to Gemini or write to MongoDB.

The official NVD 2026 yearly JSON feed is about 493 MB uncompressed (approximately 42 MB as a ZIP at the current published snapshot). The acquisition script keeps both the archive and extracted JSON under `raw/nvd/`, then the normalizer streams CVE records into the searchable corpus.

## Keep benchmark data separate from RAG text

CIC-IDS2017 is a labeled network intrusion-detection benchmark, not a general knowledge corpus. Its official download includes packet captures and labeled/derived flow data; the complete dataset is large (about 50 GB unpacked). Use selected CSV/flow features only for a separately designed detection-model evaluation. Do not embed raw PCAPs or flow rows as if they were explanatory documents. The source asks researchers to cite its paper, and its page does not state a simple reusable open-data license, so verify the terms before redistribution or non-research use.

## Before indexing

- Normalize each source into small, source-linked text chunks; retain a stable source ID, upstream identifier, title, URL, version/date, and license.
- Keep structured fields (CVE, CVSS, CWE, ATT&CK ID, dates) as metadata as well as searchable text.
- Preserve the original raw file and SHA-256 checksum so transformed data can be rebuilt and audited.
- Deduplicate by upstream ID plus source version. Rebuild the local BM25 token index only for changed records; mark removed or revoked records instead of silently losing history.
- Keep indexing offline from LLM calls. Query-time generation receives only a compact, source-linked evidence context; exclude secrets, personal data, malicious executable samples, and operational packet captures.
- Keep a held-out evaluation set separate from documents used to build the retrieval index.

## Prepare and index the corpus

Regenerate normalized JSONL documents offline:

```powershell
..\backend\python313\python.exe .\prepare_index_documents.py
```

Then, from `Application\backend`, build the local token-frequency index and upsert it into the configured MongoDB collection:

```powershell
.\python313\python.exe -m app.scripts.index_sources
```

The source indexer uses local tokenization and BM25 metadata only: it makes no Gemini requests and writes no vectors. It skips unchanged records and can resume after an interrupted run. Use `--limit 100` for a partial load; omit `--limit` for the full selected corpus. The old `ingest_datasets` and `ingest_seed_knowledge` commands remain compatibility aliases for this local indexer. The backend scan is capped at 5,000 records for this prototype.

At query time, deterministic prompt optimization classifies the question, applies a context character budget, assigns citation labels, and passes the evidence plus a separate safety-focused system instruction to the generation model. Prompt optimization itself does not call an LLM. The answer validator requires a citation on each sentence, checks IDs and numbers against the exact supplied excerpts, and applies a configurable lexical-overlap threshold (`CITATION_MIN_TOKEN_OVERLAP`). This is a conservative grounding heuristic, not semantic entailment proof; it can abstain on valid paraphrases.

Only the selected active ATT&CK techniques, mitigations, tactics, all KEV entries, the small curated starter set, and downloaded NVD 2.0 yearly CVE feeds are prepared. Groups, malware/tool profiles, and CISA advisories are not yet included.

## Evaluate retrieval quality

The 44-question held-out query set lives in `evaluation/retrieval_questions.jsonl`; it includes exact-ID and paraphrase cases, with extra ATT&CK coverage for discovery, obfuscation, public-facing applications, remote services, and mitigations. Questions are separate from indexed documents. The evaluator reads the normalized corpus, applies the same BM25 scoring function as the API, validates that every expected source ID exists, and writes per-query rankings plus aggregate metrics to `evaluation/latest-results.json`. It runs offline and does not connect to MongoDB or Gemini.

From `Application\backend`, run:

```powershell
.\python313\python.exe ..\Datasets\evaluate_retrieval.py
```

For a read-only comparison against the configured MongoDB collection, run from the same backend folder:

```powershell
.\python313\python.exe ..\Datasets\evaluate_retrieval.py --mongo
```

This mode performs a ping and read-only document queries/counts; it does not write to MongoDB or call Gemini. The saved comparison is `evaluation/mongo-results.json`. On 2026-10-27, MongoDB contained 2,524 text documents, all marked `bm25-local-v1`; all expected IDs were present, and the saved 31-question live comparison had 100% top-1 agreement and 1.000 mean top-five Jaccard against offline rankings.

Track Recall@5, mean reciprocal rank (MRR), and top-1 accuracy as the corpus or ranker changes. `evaluation/targeted-baseline-results.json` preserves the 44-question result before targeted query normalization changes; `evaluation/latest-results.json` is the current result. The targeted baseline scored 77.3% Recall@5, 0.611 MRR, and 47.7% top-1 accuracy. The current ranker scores 100%, 0.772, and 61.4%, respectively. Scoped ATT&CK phrase expansion and technique-intent scoring improved paraphrases without rebuilding the index. Previously weak cases now rank at 1 (`attack_operating_system_discovery`), 2 (`attack_domain_account_subtechnique`), and 4 (`attack_system_information_discovery`). The broader host-information paraphrase ranks T1082 at 3. The older 31-question results remain in `evaluation/expanded-baseline-results.json`; the corrected 12-question comparison remains in `evaluation/baseline-results.json`. These small diagnostic sets are not statistically representative quality claims. Inspect per-query rankings and periodically compare with MongoDB before expanding the corpus.

## Compare evidence gate policies

From `Application\backend`, run:

```powershell
.\python313\python.exe ..\Datasets\evaluate_evidence_gate.py
```

This compares the current policy (relevance AND coverage, with exact-identifier override) against no gate, relevance-only, and coverage-only on the retrieval questions plus the hand-authored out-of-corpus controls in `evaluation/evidence_gate_unanswerable.jsonl`. Results are written to `evaluation/evidence-gate-results.json`. The out-of-corpus pass rate estimates how often a policy would allow generation despite the expected answer being outside the indexed corpus; it is not an observed unsupported-answer rate. The script measures only local gate-decision latency. Citation validity is explicitly unmeasured because this benchmark has no generated-answer judgments. Review and expand the negative controls before making reliability claims.

The 40-test backend unit suite passes for the current ranker. The app health endpoint currently reports MongoDB healthy and answer generation configured. A separate read-only `--mongo` benchmark attempt ended in a suppressed `AutoReconnect`, so live parity for all 44 questions remains unverified; rerun that comparison when the Atlas connection is stable. The successful end-to-end UI request confirmed a live MongoDB query and Gemini response, but that is not a substitute for corpus-wide live ranking parity.
