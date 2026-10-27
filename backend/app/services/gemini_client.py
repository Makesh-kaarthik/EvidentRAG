"""Small REST client used only for final grounded answer generation."""

import asyncio
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.config import settings

_API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"


def _post_json(url: str, payload: dict) -> dict:
    if not settings.gemini_api_key.strip():
        raise RuntimeError("GEMINI_API_KEY is missing from the backend environment.")

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": settings.gemini_api_key,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=40) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        # Do not include response bodies: they can contain request details.
        raise RuntimeError(f"Gemini API returned HTTP {error.code}.") from None
    except (URLError, TimeoutError) as error:
        raise RuntimeError(f"Gemini API request failed ({type(error).__name__}).") from None


async def generate_grounded_answer(
    prompt: str,
    *,
    system_instruction: str | None = None,
    model: str | None = None,
) -> str:
    model = model or settings.gemini_generation_model
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 300,
        },
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
    response = await asyncio.to_thread(
        _post_json,
        f"{_API_ROOT}/{model}:generateContent",
        payload,
    )
    candidates = response.get("candidates", [])
    if not candidates:
        raise RuntimeError("Gemini returned no answer candidate.")
    parts = candidates[0].get("content", {}).get("parts", [])
    answer = "".join(part.get("text", "") for part in parts).strip()
    if not answer:
        raise RuntimeError("Gemini returned an empty answer.")
    return answer
