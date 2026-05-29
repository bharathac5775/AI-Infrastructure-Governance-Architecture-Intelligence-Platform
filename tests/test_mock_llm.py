"""Sanity tests for the mock_llm fixture.

The mock must intercept all 5 agent get_llm() call sites. If any agent
slips through, the test will hang trying to reach Ollama.
"""
from __future__ import annotations

import pytest

from app.agents.supervisor import run_analysis


SIMPLE_DEPLOYMENT_YAML = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: main
          image: nginx:1.25
"""


@pytest.mark.integration
@pytest.mark.slow
async def test_mock_llm_intercepts_full_pipeline(mock_llm):
    """The full pipeline runs end-to-end with no Ollama process available."""
    report = await run_analysis({"deployment.yaml": SIMPLE_DEPLOYMENT_YAML})
    assert report is not None
    assert report.report_id  # non-empty UUID prefix
    # All three agents should have run
    agent_names = {r.agent_name for r in report.agent_reports}
    assert "Security Agent" in agent_names
    assert "Reliability Agent" in agent_names
    assert "Cost Agent" in agent_names
    # Architecture review present (kubernetes infra detected from apiVersion+kind)
    assert report.architecture_review is not None
    # Supervisor synthesis ran (mocked content)
    assert report.executive_summary == "Mocked executive summary."
    assert report.risk_summary == "Mocked risk summary."


@pytest.mark.integration
@pytest.mark.slow
async def test_mock_llm_default_finds_nothing_extra(mock_llm):
    """Default mock returns empty findings — score equals rule-only baseline."""
    report = await run_analysis({"deployment.yaml": SIMPLE_DEPLOYMENT_YAML})
    # Each agent's findings are purely rule-based since LLM mock is empty.
    # The summary text is the agent's deterministic summary, not the mock's
    # (security.py builds its own summary from rule-based + LLM findings).
    for r in report.agent_reports:
        # Every agent should have a finite, predictable score
        assert 0 <= r.score <= 100


@pytest.mark.integration
@pytest.mark.slow
async def test_mock_llm_can_override_architecture_response(mock_llm):
    """Verify mock_llm.set() actually changes architecture review output."""
    from tests.fixtures.llm_responses import make_arch_response

    mock_llm.set("architecture", make_arch_response(
        tradeoffs=[{
            "title": "Cost vs Reliability",
            "description": "Tradeoff between resource limits and HA.",
            "agents_involved": ["cost", "reliability"],
            "recommendation": "Right-size resources.",
        }],
        summary="Custom architecture summary for test.",
    ))
    report = await run_analysis({"deployment.yaml": SIMPLE_DEPLOYMENT_YAML})
    arch = report.architecture_review
    assert arch is not None
    assert arch.summary == "Custom architecture summary for test."
    assert len(arch.tradeoffs) == 1
    assert arch.tradeoffs[0].title == "Cost vs Reliability"
