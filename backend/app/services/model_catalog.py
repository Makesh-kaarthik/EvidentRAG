"""OpenRouter text models exposed to the query UI and API."""

_MODELS = (
    {
        "id": "gemini-flash-lite-latest",
        "name": "Gemini Flash-Lite Latest",
        "description": "Fast Gemini generation",
        "provider": "Gemini",
        "model_id": "gemini-flash-lite-latest",
    },
    {
        "id": "openrouter:nvidia/nemotron-3.5-lightning:free",
        "name": "OpenRouter · Nemotron 3.5 Lightning (free)",
        "description": "Fast OpenRouter model · verified available",
        "provider": "OpenRouter",
        "model_id": "nvidia/nemotron-3.5-lightning:free",
    },
    {
        "id": "openrouter:free",
        "name": "OpenRouter · Free Model Router",
        "description": "Routes to an available free model",
        "provider": "OpenRouter",
        "model_id": "openrouter/free",
    },
)


def available_models() -> list[dict[str, str]]:
    """Return the OpenRouter models verified for this application."""
    return list(_MODELS)


def default_model_id() -> str:
    """Return the recommended available model's UI identifier."""
    return _MODELS[0]["id"]


def is_allowed_model(model: str) -> bool:
    return model in {entry["id"] for entry in available_models()}


def get_model(model: str) -> dict[str, str]:
    """Resolve a UI selection to its trusted provider and upstream model ID."""
    return next(entry for entry in available_models() if entry["id"] == model)
