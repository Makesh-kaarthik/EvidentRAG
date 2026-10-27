# EvidentRAG

EvidentRAG is a cybersecurity question-answering application that retrieves evidence from MITRE ATT&CK, CISA KEV, and NVD sources, then produces cited answers through configured language-model providers.

## Project layout

- `backend/` — FastAPI service, retrieval, evidence checks, and tests
- `frontend/` — React and Vite user interface
- `Datasets/` — dataset preparation, evaluation scripts, source catalog, and licenses
- `Datasets/processed/evidence-policy-benchmark-live.json` — latest live Atlas benchmark summary
- `Datasets/processed/evidence-policy-benchmark-cases-live.csv` — per-case live results

Downloaded source payloads, local credentials, Python environments, frontend dependencies, and build output are excluded from Git.

## Run locally

1. Create `backend/.env` from `backend/.env.example` and fill in your own MongoDB URI and provider API keys. Never commit this file.
2. Install backend dependencies with Python 3.13:

   ```powershell
   cd backend
   py -3.13 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

3. In another terminal, install frontend dependencies and start the UI:

   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

The backend expects an indexed MongoDB collection. See [`Datasets/README.md`](Datasets/README.md) for source acquisition, processing, licensing, and indexing steps.

## Reproduce the evidence-policy benchmark

From `backend/`, run the offline benchmark against the processed corpus:

```powershell
python -m app.scripts.benchmark_evidence
```

To query the configured live MongoDB collection instead:

```powershell
python -m app.scripts.benchmark_evidence --live
```

The benchmark compares `no_gate`, `relevance_only`, `coverage_only`, and the current policy on a fixed set of 12 answerable attack scenarios and 6 out-of-scope prompts. It records unsupported-answer proxies, false abstentions, retrieval hits, gold-source availability, and latency. The citation metric checks whether the expected source is available; it does not assess generated claim entailment. Timing excludes LLM generation and depends on the network and database when run live.

The committed live report was measured against 706 ATT&CK records in `CyberEvidentRAG.knowledge_chunks`. Results are a small development benchmark, not a broad generalization claim.
