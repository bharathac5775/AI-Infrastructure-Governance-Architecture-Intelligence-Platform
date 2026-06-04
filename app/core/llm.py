"""Provider-agnostic LLM factory.

Every agent in the platform calls :func:`get_llm` and gets back a
LangChain ``BaseChatModel`` configured for whatever provider is selected
in :data:`app.config.settings.LLM_PROVIDER`. The agents themselves are
provider-blind — they use the standard ``prompt | llm | ainvoke``
LangChain pipeline, which works identically across Ollama, Anthropic,
OpenAI, and Google.

Switching providers is purely an .env change:

.. code-block:: bash

    # Default — local, free, slow-ish
    LLM_PROVIDER=ollama
    OLLAMA_MODEL=gemma4:E2B

    # Switch to Claude
    LLM_PROVIDER=anthropic
    ANTHROPIC_API_KEY=sk-ant-...
    ANTHROPIC_MODEL=claude-sonnet-4-5

    # Switch to GPT
    LLM_PROVIDER=openai
    OPENAI_API_KEY=sk-...
    OPENAI_MODEL=gpt-4o

    # Switch to Gemini
    LLM_PROVIDER=google
    GOOGLE_API_KEY=AIza...
    GOOGLE_MODEL=gemini-1.5-pro

Imports are lazy: a user running on Ollama doesn't need
``langchain-anthropic`` or ``langchain-openai`` installed. Cloud
providers are validated on first use — you'll get a clear ``LLMConfigError``
if the API key is missing instead of a cryptic LangChain stack trace.
"""
from __future__ import annotations

from typing import Any

from app.config import settings


class LLMConfigError(RuntimeError):
    """Raised when the configured LLM provider is misconfigured (unknown
    provider, missing API key, missing optional dependency, etc.)."""


_VALID_PROVIDERS = ("ollama", "anthropic", "openai", "google")


def get_llm(temperature: float = 0.1, num_ctx: int = 4096) -> Any:
    """Return a LangChain chat model for the configured provider.

    Args:
        temperature: Sampling temperature, 0.0–1.0. Defaults to 0.1
            (deterministic-ish — this platform prefers consistency over
            creativity).
        num_ctx: Ollama-only context-window size. Silently ignored by
            cloud providers, which use their default context windows
            (Claude ~200k, GPT-4o 128k, Gemini 1M).

    Raises:
        LLMConfigError: If the provider is unknown, the required API key
            is missing, or the provider's LangChain package isn't installed.
    """
    provider = (settings.LLM_PROVIDER or "ollama").strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise LLMConfigError(
            f"Unknown LLM_PROVIDER {provider!r}. "
            f"Valid options: {', '.join(_VALID_PROVIDERS)}."
        )

    if provider == "ollama":
        return _build_ollama(temperature=temperature, num_ctx=num_ctx)
    if provider == "anthropic":
        return _build_anthropic(temperature=temperature)
    if provider == "openai":
        return _build_openai(temperature=temperature)
    if provider == "google":
        return _build_google(temperature=temperature)
    # Unreachable thanks to the validation above
    raise LLMConfigError(f"No factory for provider {provider!r}.")


# ---------------------------------------------------------------------------
# Per-provider builders. Each lazily imports its LangChain package so users
# only need to install the providers they actually use.
# ---------------------------------------------------------------------------


def _build_ollama(temperature: float, num_ctx: int):
    try:
        from langchain_ollama import ChatOllama
    except ImportError as e:
        raise LLMConfigError(
            "langchain-ollama is not installed. Run: pip install langchain-ollama"
        ) from e
    return ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_BASE_URL,
        temperature=temperature,
        num_ctx=num_ctx,
        timeout=settings.LLM_TIMEOUT_SECONDS,
    )


def _build_anthropic(temperature: float):
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as e:
        raise LLMConfigError(
            "langchain-anthropic is not installed. "
            "Run: pip install langchain-anthropic"
        ) from e
    if not settings.ANTHROPIC_API_KEY:
        raise LLMConfigError(
            "ANTHROPIC_API_KEY is not set. Add it to your .env or environment."
        )
    return ChatAnthropic(
        model=settings.ANTHROPIC_MODEL,
        api_key=settings.ANTHROPIC_API_KEY,
        temperature=temperature,
        timeout=settings.LLM_TIMEOUT_SECONDS,
        max_tokens=4096,
    )


def _build_openai(temperature: float):
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as e:
        raise LLMConfigError(
            "langchain-openai is not installed. "
            "Run: pip install langchain-openai"
        ) from e
    if not settings.OPENAI_API_KEY:
        raise LLMConfigError(
            "OPENAI_API_KEY is not set. Add it to your .env or environment."
        )
    kwargs = {
        "model": settings.OPENAI_MODEL,
        "api_key": settings.OPENAI_API_KEY,
        "temperature": temperature,
        "timeout": settings.LLM_TIMEOUT_SECONDS,
    }
    # Optional override for Azure OpenAI / OpenRouter / local proxies
    if settings.OPENAI_BASE_URL:
        kwargs["base_url"] = settings.OPENAI_BASE_URL
    return ChatOpenAI(**kwargs)


def _build_google(temperature: float):
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as e:
        raise LLMConfigError(
            "langchain-google-genai is not installed. "
            "Run: pip install langchain-google-genai"
        ) from e
    if not settings.GOOGLE_API_KEY:
        raise LLMConfigError(
            "GOOGLE_API_KEY is not set. Add it to your .env or environment."
        )
    return ChatGoogleGenerativeAI(
        model=settings.GOOGLE_MODEL,
        google_api_key=settings.GOOGLE_API_KEY,
        temperature=temperature,
        timeout=settings.LLM_TIMEOUT_SECONDS,
    )
