from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Cyber EvidentRAG API"
    app_version: str = "0.2.0"
    debug: bool = True
    frontend_url: str = "http://localhost:5173"

    mongodb_uri: str
    mongodb_database: str = "CyberEvidentRAG"
    knowledge_collection: str = "knowledge_chunks"
    conversations_collection: str = "conversations"
    max_conversation_turns: int = 6
    retrieval_candidate_limit: int = 100
    rag_top_k: int = 5

    gemini_api_key: str = ""
    gemini_generation_model: str = "gemini-flash-lite-latest"
    openrouter_api_key: str = ""

    bm25_k1: float = 1.5
    bm25_b: float = 0.75
    bm25_identifier_boost: float = 8.0
    bm25_title_prefix_boost: float = 14.0
    bm25_title_phrase_boost: float = 4.0
    bm25_technique_over_tactic_boost: float = 5.0
    bm25_score_saturation: float = 6.0
    evidence_min_local_relevance: float = 0.12
    evidence_min_query_coverage: float = 0.30
    prompt_context_max_chars: int = 12000
    citation_min_token_overlap: float = 0.30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
