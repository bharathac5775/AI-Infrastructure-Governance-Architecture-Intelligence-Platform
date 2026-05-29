"""Shared pytest fixtures for the AI Infrastructure Governance Platform test suite.

Fixtures defined here:
- sample_loader: callable to read sample files from `samples/`
- expected_scores: lazy-loaded YAML manifest of pinned per-sample expectations
- mock_llm: monkeypatches app.core.llm.get_llm in every importer's namespace,
  returns a fake Runnable that routes to canned JSON by prompt content.

The mock_llm fixture must be opted into explicitly. Most rule-unit tests don't
need it (they call sync rule functions directly).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest
import yaml
from langchain_core.runnables import Runnable

REPO_ROOT = Path(__file__).parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
EXPECTED_SCORES_PATH = Path(__file__).parent / "expected_scores.yaml"


@pytest.fixture
def sample_loader() -> Callable[[str], str]:
    """Return a callable that reads a sample file from the repo's samples/ dir."""

    def _load(filename: str) -> str:
        path = SAMPLES_DIR / filename
        return path.read_text(encoding="utf-8")

    return _load


@pytest.fixture(scope="session")
def expected_scores() -> dict:
    """Return the parsed expected_scores.yaml manifest, or an empty dict if absent."""
    if not EXPECTED_SCORES_PATH.exists():
        return {"samples": {}}
    return yaml.safe_load(EXPECTED_SCORES_PATH.read_text(encoding="utf-8")) or {"samples": {}}


# ---------------------------------------------------------------------------
# LLM mock — see tests/fixtures/llm_responses.py for canned payloads.
#
# GOTCHA: each agent module does `from app.core.llm import get_llm`, which
# binds the name at import time. Patching only `app.core.llm.get_llm` does
# NOT redirect lookups inside `app.agents.security`. We must patch the
# imported reference in every importer's namespace.
# ---------------------------------------------------------------------------


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeRunnable(Runnable):
    """Drop-in replacement for ChatOllama. Implements ainvoke()/invoke().

    Plugs into LangChain's `prompt | llm` pattern: the resulting RunnableSequence
    will render the prompt and pass the PromptValue to our ainvoke. We inherit
    from Runnable so coerce_to_runnable accepts us in pipe composition.
    """

    def __init__(self, response_map: dict):
        super().__init__()
        self._response_map = response_map

    async def ainvoke(self, input_, config=None, **kwargs):
        prompt_text = self._extract_prompt_text(input_)
        agent_key = _route_by_prompt(prompt_text)
        payload = self._response_map.get(agent_key, {})
        return _FakeMessage(json.dumps(payload))

    def invoke(self, input_, config=None, **kwargs):
        import asyncio
        return asyncio.run(self.ainvoke(input_, config))

    @staticmethod
    def _extract_prompt_text(input_) -> str:
        # PromptValue has .to_string(); plain dicts/strings degrade gracefully
        if hasattr(input_, "to_string"):
            try:
                return input_.to_string()
            except Exception:
                return str(input_)
        if hasattr(input_, "to_messages"):
            try:
                msgs = input_.to_messages()
                return "\n".join(getattr(m, "content", str(m)) for m in msgs)
            except Exception:
                return str(input_)
        return str(input_)


def _route_by_prompt(prompt_text: str) -> str:
    """Identify which agent is invoking based on system-prompt content.

    Order matters — the supervisor prompt contains 'Architecture Review' as
    well as 'executive_summary', so check for the supervisor signature FIRST
    before the architecture-reviewer signature.
    """
    pt = prompt_text.lower()
    if "executive_summary" in pt or "review supervisor" in pt:
        return "supervisor"
    if "architecture reviewer agent" in pt or "cross-cutting gap rule" in pt:
        return "architecture"
    if "security agent" in pt or "security analyst" in pt:
        return "security"
    if "reliability agent" in pt or "reliability engineer" in pt or "site reliability" in pt:
        return "reliability"
    if "cost agent" in pt or "finops" in pt or "cost optimization" in pt:
        return "cost"
    return "supervisor"


class MockLLMHandle:
    """Returned by the mock_llm fixture. Tests can override per-agent responses."""

    def __init__(self, response_map: dict):
        self._response_map = response_map

    def set(self, agent_key: str, response: dict) -> None:
        """Override the canned JSON for a specific agent route."""
        self._response_map[agent_key] = response

    @property
    def response_map(self) -> dict:
        return self._response_map


@pytest.fixture
def mock_llm(monkeypatch):
    """Replace get_llm() in every agent module with a fake that returns canned JSON.

    Default behavior: every agent gets an "empty" response (no extra findings,
    no architecture gaps), so rule-based findings dominate and full-pipeline
    scores match rules-only scores closely.

    Override per-test:
        def test_x(mock_llm):
            mock_llm.set("architecture", make_arch_response(gaps=[...]))
    """
    # Import here so the fixture file can be discovered without yaml at import time
    from tests.fixtures.llm_responses import EMPTY_RESPONSES

    response_map = {k: dict(v) for k, v in EMPTY_RESPONSES.items()}
    fake = _FakeRunnable(response_map)

    def _get_llm(*args, **kwargs):
        return fake

    # Patch in every importer's namespace — see GOTCHA in module docstring.
    monkeypatch.setattr("app.core.llm.get_llm", _get_llm)
    monkeypatch.setattr("app.agents.security.get_llm", _get_llm)
    monkeypatch.setattr("app.agents.reliability.get_llm", _get_llm)
    monkeypatch.setattr("app.agents.cost.get_llm", _get_llm)
    monkeypatch.setattr("app.agents.architecture_reviewer.get_llm", _get_llm)
    monkeypatch.setattr("app.agents.supervisor.get_llm", _get_llm)

    return MockLLMHandle(response_map)

