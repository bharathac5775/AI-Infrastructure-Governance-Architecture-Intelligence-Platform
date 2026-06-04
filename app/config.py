"""Configuration: env-driven settings for the platform.

LLM provider is selected via ``LLM_PROVIDER`` (default: ``ollama``). Each
provider has its own model + key/url settings. To switch providers, the
user only needs to set environment variables in ``.env`` — no code change
or test change is required. See ``.env.example`` for documented examples.

Supported providers (Phase 3.4):
- ``ollama``     : local Ollama (default — no API key, runs on your laptop)
- ``anthropic``  : Claude via the Anthropic API
- ``openai``     : GPT-4o etc. via the OpenAI API
- ``google``     : Gemini via the Google Generative AI API

Adding a new provider is a 10-line patch to :mod:`app.core.llm`; this
config module already exposes a ``get_provider_config()`` helper for it.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # ---- LLM provider selection (Phase 3.4) ----
    # One of: "ollama", "anthropic", "openai", "google"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "ollama").strip().lower()

    # ---- Ollama (default, local) ----
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:E2B")

    # ---- Anthropic (Claude) ----
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

    # ---- OpenAI (GPT) ----
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    # Optional: override base URL for Azure OpenAI / proxies
    OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "")

    # ---- Google (Gemini) ----
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    GOOGLE_MODEL: str = os.getenv("GOOGLE_MODEL", "gemini-1.5-pro")

    # ---- Generic LLM tuning (provider-agnostic) ----
    # Per-call timeout in seconds. Cloud APIs are fast; local Ollama is slow.
    LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "300"))

    # ---- Platform settings (unchanged) ----
    UPLOAD_DIR: str = "uploads"
    CHROMA_DIR: str = "chroma_data"
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: set = {".yaml", ".yml", ".tf", ".json", ".hcl", ".tgz"}


settings = Settings()
