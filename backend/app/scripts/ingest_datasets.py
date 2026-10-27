"""Compatibility command; dataset ingestion is now a local BM25 index build."""

from app.scripts.index_sources import main


if __name__ == "__main__":
    main()
