from typing import List

from pydantic import BaseModel, Field, field_validator

from app.services.model_catalog import is_allowed_model


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    model: str | None = Field(default=None, min_length=1, max_length=100)
    conversation_id: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str | None) -> str | None:
        if value is not None and not is_allowed_model(value):
            raise ValueError("Unsupported Gemini model selection.")
        return value


class Source(BaseModel):
    title: str
    source: str
    score: float
    url: str | None = None
    citation_id: str | None = None


class PipelineStatus(BaseModel):
    query_processing: str
    hybrid_retrieval: str
    cross_encoder_reranking: str
    prompt_optimization: str
    evidence_verification: str
    response_generation: str


class QueryResponse(BaseModel):
    query: str
    answer: str
    confidence: float
    coverage: float
    relevance: float
    sources: List[Source]
    pipeline: PipelineStatus
    sufficient: bool = False
    abstained: bool = False
    model: str | None = None
