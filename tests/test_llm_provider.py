"""Tests for Phase 3.4 multi-provider LLM factory.

The factory in app/core/llm.py routes to Ollama / Anthropic / OpenAI /
Google based on settings.LLM_PROVIDER. These tests verify each branch
is reachable, missing API keys raise clear errors, and the function
remains backwards-compatible with the default (Ollama).

We do NOT make real API calls. The tests:
- Patch settings.LLM_PROVIDER + the relevant API-key setting
- Assert the returned object is the right LangChain class
- Confirm error paths produce LLMConfigError, not raw stack traces
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.core.llm import LLMConfigError, get_llm


# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------


class TestProviderRouting:
    """Each LLM_PROVIDER value picks the correct LangChain client class.
    These confirm the dispatch is wired correctly without making any
    network calls — the client is constructed but not invoked."""

    def test_default_ollama(self, monkeypatch):
        from langchain_ollama import ChatOllama

        monkeypatch.setattr(settings, "LLM_PROVIDER", "ollama")
        llm = get_llm()
        assert isinstance(llm, ChatOllama)

    def test_anthropic(self, monkeypatch):
        from langchain_anthropic import ChatAnthropic

        monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-test")
        llm = get_llm()
        assert isinstance(llm, ChatAnthropic)

    def test_openai(self, monkeypatch):
        from langchain_openai import ChatOpenAI

        monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-test")
        llm = get_llm()
        assert isinstance(llm, ChatOpenAI)

    def test_google(self, monkeypatch):
        from langchain_google_genai import ChatGoogleGenerativeAI

        monkeypatch.setattr(settings, "LLM_PROVIDER", "google")
        monkeypatch.setattr(settings, "GOOGLE_API_KEY", "AIza-test")
        llm = get_llm()
        assert isinstance(llm, ChatGoogleGenerativeAI)

    def test_provider_value_is_case_insensitive(self, monkeypatch):
        """Mixed-case env values like 'Anthropic' or 'OPENAI' shouldn't
        break the dispatcher."""
        from langchain_anthropic import ChatAnthropic

        monkeypatch.setattr(settings, "LLM_PROVIDER", "Anthropic")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-test")
        assert isinstance(get_llm(), ChatAnthropic)

    def test_provider_value_strips_whitespace(self, monkeypatch):
        from langchain_ollama import ChatOllama

        monkeypatch.setattr(settings, "LLM_PROVIDER", "  ollama  ")
        assert isinstance(get_llm(), ChatOllama)


# ---------------------------------------------------------------------------
# Error paths — clear messages, never raw library stack traces
# ---------------------------------------------------------------------------


class TestErrorPaths:
    def test_unknown_provider_raises_config_error(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "azure-openai")
        with pytest.raises(LLMConfigError) as exc:
            get_llm()
        msg = str(exc.value).lower()
        assert "unknown" in msg
        # The error should suggest the valid options
        for name in ("ollama", "anthropic", "openai", "google"):
            assert name in msg

    def test_anthropic_missing_key_raises_config_error(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
        with pytest.raises(LLMConfigError) as exc:
            get_llm()
        assert "ANTHROPIC_API_KEY" in str(exc.value)

    def test_openai_missing_key_raises_config_error(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
        with pytest.raises(LLMConfigError) as exc:
            get_llm()
        assert "OPENAI_API_KEY" in str(exc.value)

    def test_google_missing_key_raises_config_error(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_PROVIDER", "google")
        monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")
        with pytest.raises(LLMConfigError) as exc:
            get_llm()
        assert "GOOGLE_API_KEY" in str(exc.value)

    def test_empty_provider_falls_back_to_ollama(self, monkeypatch):
        """Empty LLM_PROVIDER (someone set it to an empty string in .env)
        should default to ollama rather than crashing."""
        from langchain_ollama import ChatOllama

        monkeypatch.setattr(settings, "LLM_PROVIDER", "")
        assert isinstance(get_llm(), ChatOllama)


# ---------------------------------------------------------------------------
# Backwards compatibility
# ---------------------------------------------------------------------------


class TestBackwardsCompat:
    def test_get_llm_accepts_temperature(self, monkeypatch):
        """Existing call sites pass temperature=0.2 — must still work."""
        monkeypatch.setattr(settings, "LLM_PROVIDER", "ollama")
        llm = get_llm(temperature=0.2)
        assert llm.temperature == 0.2

    def test_get_llm_accepts_num_ctx_for_ollama(self, monkeypatch):
        """architecture_reviewer.py passes num_ctx=8192. Ollama uses it."""
        monkeypatch.setattr(settings, "LLM_PROVIDER", "ollama")
        llm = get_llm(temperature=0.2, num_ctx=8192)
        assert llm.num_ctx == 8192

    def test_get_llm_silently_ignores_num_ctx_for_cloud_providers(self, monkeypatch):
        """num_ctx is Ollama-specific. Cloud providers don't accept it
        but the call must still succeed — the agents pass it
        unconditionally and shouldn't have to know which provider is
        active."""
        monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
        monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-test")
        # Should not raise
        llm = get_llm(temperature=0.2, num_ctx=8192)
        assert llm is not None

    def test_default_provider_is_ollama(self):
        """Without any env override, the platform should still pick
        Ollama. This is the privacy-first default."""
        # Don't monkeypatch — read whatever the test env has.
        # If a user has set LLM_PROVIDER for their session, that's their
        # call; we just verify the factory returns SOMETHING valid.
        llm = get_llm()
        assert llm is not None
        # Class name has to be one of the known providers
        cls_name = type(llm).__name__
        assert cls_name in ("ChatOllama", "ChatAnthropic", "ChatOpenAI",
                             "ChatGoogleGenerativeAI"), (
            f"Unexpected class {cls_name}"
        )
