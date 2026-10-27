"""MongoDB persistence for short, browser-visible investigation conversations."""

from datetime import datetime, timezone
from uuid import uuid4

from pymongo import ReturnDocument

from app.core.config import settings
from app.core.database import get_database


MAX_TURNS_PER_CONVERSATION = settings.max_conversation_turns


def _collection():
    return get_database()[settings.conversations_collection]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public(document: dict) -> dict:
    document.pop("_id", None)
    return document


def create_conversation() -> dict:
    now = _now()
    conversation = {
        "_id": str(uuid4()),
        "title": "New Investigation",
        "created_at": now,
        "updated_at": now,
        "turn_count": 0,
        "messages": [],
    }
    _collection().insert_one(conversation)
    return _public(conversation)


def list_conversations() -> list[dict]:
    return [
        {
            "id": item["_id"],
            "title": item.get("title", "New Investigation"),
            "updated_at": item.get("updated_at"),
            "turn_count": int(item.get("turn_count", 0)),
        }
        for item in _collection().find(
            {}, {"title": 1, "updated_at": 1, "turn_count": 1}
        ).sort("updated_at", -1).limit(100)
    ]


def get_conversation(conversation_id: str) -> dict | None:
    document = _collection().find_one({"_id": conversation_id})
    if document is None:
        return None
    document["id"] = document.pop("_id")
    return document


def reserve_user_turn(conversation_id: str, query: str) -> dict:
    """Atomically append a question only while the conversation has capacity."""
    now = _now()
    user_message = {
        "id": str(uuid4()),
        "type": "user",
        "content": query,
        "created_at": now,
    }
    collection = _collection()
    existing = collection.find_one_and_update(
        {"_id": conversation_id, "turn_count": {"$lt": MAX_TURNS_PER_CONVERSATION}},
        {
            "$inc": {"turn_count": 1},
            "$push": {"messages": user_message},
            "$set": {"updated_at": now},
        },
        return_document=ReturnDocument.AFTER,
    )
    if existing is None:
        if collection.find_one({"_id": conversation_id}, {"_id": 1}):
            raise ValueError("conversation_limit")
        raise LookupError("conversation_not_found")

    # Set the title from the first submitted question without overwriting titles
    # once a conversation has begun.
    if int(existing.get("turn_count", 0)) == 1:
        collection.update_one(
            {"_id": conversation_id, "turn_count": 1},
            {"$set": {"title": query[:64], "updated_at": now}},
        )
        existing["title"] = query[:64]
    existing["id"] = existing.pop("_id")
    return {"conversation": existing, "user_message": user_message}


def append_assistant_message(conversation_id: str, message: dict) -> None:
    stored = {**message, "id": str(uuid4()), "type": "assistant", "created_at": _now()}
    _collection().update_one(
        {"_id": conversation_id},
        {"$push": {"messages": stored}, "$set": {"updated_at": stored["created_at"]}},
    )
