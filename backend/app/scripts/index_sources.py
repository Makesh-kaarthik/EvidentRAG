"""Build the MongoDB BM25 source index locally, without calling an LLM."""

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from pymongo import ReplaceOne
from pymongo.errors import ConnectionFailure, NetworkTimeout

from app.core.config import settings
from app.core.database import close_mongodb_connection, connect_to_mongodb
from app.services.text_index import term_frequencies


DATASET_ROOT = Path(__file__).resolve().parents[3] / "Datasets"
DOCUMENTS_PATH = DATASET_ROOT / "processed" / "index_documents.jsonl"
INDEX_VERSION = "bm25-local-v1"


def _mongo_retry(operation, label: str):
    for attempt in range(1, 5):
        try:
            return operation()
        except (ConnectionFailure, NetworkTimeout) as error:
            if attempt == 4:
                raise
            delay = attempt * 2
            print(
                f"MongoDB {label} retry {attempt}/3 after "
                f"{type(error).__name__}; waiting {delay}s."
            )
            time.sleep(delay)


def load_documents(limit: int | None = None) -> list[dict]:
    if not DOCUMENTS_PATH.exists():
        raise FileNotFoundError(
            f"Prepared source corpus missing: {DOCUMENTS_PATH}. "
            "Run Datasets/prepare_index_documents.py first."
        )
    documents = []
    with DOCUMENTS_PATH.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                documents.append(json.loads(line))
                if limit and len(documents) >= limit:
                    break
    return documents


def _index_record(document: dict) -> dict:
    text_terms = term_frequencies(document)
    record = {
        **document,
        "chunk_id": hashlib.sha256(
            f"{document['source_id']}\n{document['content_sha256']}".encode("utf-8")
        ).hexdigest(),
        "term_frequency": text_terms,
        "token_count": sum(text_terms.values()),
        "indexing_method": INDEX_VERSION,
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }
    # This is a lexical source index. Remove vectors left by the old
    # Gemini-dependent indexer instead of mixing two retrieval formats.
    record.pop("embedding", None)
    record.pop("embedding_model", None)
    record.pop("embedding_dimensions", None)
    return record


def index_sources(batch_size: int, limit: int | None = None) -> None:
    documents = load_documents(limit)
    if not documents:
        print("No source documents found; nothing to index.")
        return

    database = _mongo_retry(connect_to_mongodb, "connection")
    collection = database[settings.knowledge_collection]

    try:
        _mongo_retry(lambda: collection.create_index("source_id"), "source index setup")
        _mongo_retry(lambda: collection.create_index("source_type"), "type index setup")
        _mongo_retry(lambda: collection.create_index("upstream_id"), "identifier index setup")
        _mongo_retry(
            lambda: collection.create_index(
                [("term_frequency.$**", 1)], name="term_frequency_wildcard"
            ),
            "retrieval term index setup",
        )
        source_ids = [document["source_id"] for document in documents]
        existing_records = _mongo_retry(
            lambda: list(
                collection.find(
                    {"source_id": {"$in": source_ids}},
                    {
                        "_id": 0,
                        "source_id": 1,
                        "content_sha256": 1,
                        "indexing_method": 1,
                        "term_frequency": 1,
                        "embedding_dimensions": 1,
                    },
                )
            ),
            "resume scan",
        )
        existing = {record["source_id"]: record for record in existing_records}
        pending = [
            document
            for document in documents
            if not (
                existing.get(document["source_id"], {}).get("content_sha256")
                == document["content_sha256"]
                and existing.get(document["source_id"], {}).get("indexing_method")
                == INDEX_VERSION
                and isinstance(
                    existing.get(document["source_id"], {}).get("term_frequency"), dict
                )
                and "embedding_dimensions" not in existing.get(document["source_id"], {})
            )
        ]
        print(
            f"Prepared {len(documents)} records; already locally indexed: "
            f"{len(documents) - len(pending)}; to index: {len(pending)}."
        )
        print("Indexing method: local token normalization + BM25; no Gemini calls.")

        for offset in range(0, len(pending), batch_size):
            batch = pending[offset : offset + batch_size]
            operations = [
                ReplaceOne(
                    {"source_id": document["source_id"]},
                    _index_record(document),
                    upsert=True,
                )
                for document in batch
            ]
            _mongo_retry(
                lambda: collection.bulk_write(operations, ordered=False),
                "batch write",
            )
            print(f"Indexed {min(offset + len(batch), len(pending))}/{len(pending)} pending records.")

        print(
            f"Local source indexing complete: {len(documents)} prepared records "
            f"in {settings.knowledge_collection}."
        )
    finally:
        close_mongodb_connection()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 1000:
        parser.error("--batch-size must be between 1 and 1000.")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1.")
    index_sources(args.batch_size, args.limit)


if __name__ == "__main__":
    main()
