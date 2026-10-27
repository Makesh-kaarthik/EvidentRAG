import asyncio

from fastapi import APIRouter, HTTPException
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.core.database import get_database
from app.models.schemas import QueryRequest, QueryResponse
from app.services import conversations
from app.services.model_catalog import available_models, default_model_id
from app.services.rag_service import process_query


router = APIRouter()


@router.get("/conversations")
async def conversations_list():
    return {"conversations": conversations.list_conversations()}


@router.post("/conversations")
async def conversation_create():
    return conversations.create_conversation()


@router.get("/conversations/{conversation_id}")
async def conversation_get(conversation_id: str):
    conversation = conversations.get_conversation(conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="This investigation could not be found.")
    return conversation


@router.get("/models")
async def list_models():
    """Return the text models allowed by the configured providers."""
    return {
        "provider": "Gemini and OpenRouter",
        "default_model": default_model_id(),
        "models": available_models(),
    }


@router.post("/query", response_model=QueryResponse)
async def query_endpoint(request: QueryRequest):
    """
    Process a cybersecurity query through the RAG pipeline.
    """

    if request.conversation_id:
        try:
            conversations.reserve_user_turn(request.conversation_id, request.query.strip())
        except ValueError as error:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This investigation has reached its six-question limit. "
                    "Please start a new investigation to continue."
                ),
            ) from error
        except LookupError as error:
            raise HTTPException(status_code=404, detail="This investigation could not be found.") from error

    try:
        response = await process_query(request)
    except HTTPException as error:
        if request.conversation_id:
            conversations.append_assistant_message(
                request.conversation_id,
                {"content": error.detail or "Unable to process this question."},
            )
        raise

    if request.conversation_id:
        conversations.append_assistant_message(
            request.conversation_id,
            response.model_dump(mode="json"),
        )
    return response


@router.get("/health")
async def health_check():
    """Report database readiness and whether answer generation is configured."""
    try:
        database = get_database()
        await asyncio.to_thread(database.command, "ping")
    except (PyMongoError, RuntimeError) as error:
        raise HTTPException(
            status_code=503,
            detail="The knowledge database is unavailable.",
        ) from error

    generation_configured = bool(
        settings.gemini_api_key.strip() or settings.openrouter_api_key.strip()
    )
    return {
        "status": "healthy" if generation_configured else "degraded",
        "service": "Cyber EvidentRAG API",
        "dependencies": {
            "mongodb": "healthy",
            "answer_generation": "configured" if generation_configured else "missing_provider_api_key",
        },
    }


@router.get("/knowledge/stats")
async def knowledge_stats():
    """Return live indexed document counts for the sidebar knowledge panel."""
    try:
        collection = get_database()[settings.knowledge_collection]
        total, grouped = await asyncio.gather(
            asyncio.to_thread(collection.count_documents, {}),
            asyncio.to_thread(
                lambda: list(collection.aggregate([
                    {"$group": {"_id": "$source_type", "count": {"$sum": 1}}}
                ]))
            ),
        )
    except (PyMongoError, RuntimeError) as error:
        raise HTTPException(status_code=503, detail="Knowledge statistics are unavailable.") from error
    return {
        "total": total,
        "by_source": {item["_id"]: item["count"] for item in grouped if item.get("_id")},
    }
