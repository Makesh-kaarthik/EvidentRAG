"""OpenRouter chat-completions client for grounded answer generation."""

import asyncio
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.config import settings


_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"


def _post_json(payload: dict) -> dict:
    api_key = settings.openrouter_api_key.strip()
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is missing from the backend environment.")
    request = Request(
        _CHAT_COMPLETIONS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": settings.frontend_url,
            "X-Title": "Cyber EvidentRAG",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise RuntimeError(f"OpenRouter API returned HTTP {error.code}.") from None
    except (URLError, TimeoutError) as error:
        raise RuntimeError(f"OpenRouter request failed ({type(error).__name__}).") from None


async def generate_grounded_answer(
    prompt: str,
    *,
    model: str,
    system_instruction: str | None = None,
) -> str:
    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 700,
    }
    response = await asyncio.to_thread(_post_json, payload)
    choices = response.get("choices", [])
    answer = choices[0].get("message", {}).get("content", "").strip() if choices else ""
    if not answer:
        raise RuntimeError("OpenRouter returned an empty answer.")
    return answer
