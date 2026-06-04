"""Canned LLM responses keyed by agent type.

Each agent's `chain.ainvoke(...)` is mocked to return one of these payloads
(serialized as JSON) based on substring-matching the system prompt in
`tests/conftest.py::_route_by_prompt`.

Default behavior is "no extra findings" — rule-based findings dominate, and
full-pipeline scores match rules-only scores. Tests that exercise the
LLM-augmented path can override per-route via `mock_llm.set(key, response)`.
"""
from __future__ import annotations


EMPTY_RESPONSES: dict[str, dict] = {
    "security": {
        "findings": [],
        "summary": "No additional security issues found by AI analysis.",
    },
    "reliability": {
        "findings": [],
        "summary": "No additional reliability issues found.",
    },
    "cost": {
        "findings": [],
        "summary": "No additional cost issues found.",
    },
    "architecture": {
        "tradeoffs": [],
        "patterns_detected": [],
        "cross_cutting_gaps": [],
        "prioritized_actions": [],
        "summary": "Architecture review (mocked).",
    },
    "supervisor": {
        "executive_summary": "Mocked executive summary.",
        "risk_summary": "Mocked risk summary.",
        "recommendations": ["Mocked recommendation"],
    },
    "remediator": {
        # Default mock: returns the original file unchanged. Tests that exercise
        # the LLM remediation path override this via mock_llm.set("remediator", ...).
        "patched_content": "",
        "explanation": "Mocked remediator response (no-op).",
    },
}


def make_arch_response(
    tradeoffs: list | None = None,
    patterns: list | None = None,
    gaps: list | None = None,
    actions: list | None = None,
    summary: str = "Mocked architecture review.",
) -> dict:
    """Build an architecture-reviewer response. Useful for testing dedup filters
    by injecting specific gaps and watching them flow through the pipeline."""
    return {
        "tradeoffs": tradeoffs or [],
        "patterns_detected": patterns or [],
        "cross_cutting_gaps": gaps or [],
        "prioritized_actions": actions or [],
        "summary": summary,
    }


def make_agent_finding(
    title: str,
    description: str,
    severity: str = "medium",
    category: str = "ai-analysis",
    resource: str = "test",
    recommendation: str = "Address the issue.",
) -> dict:
    """Build an agent finding for use inside an LLM-mocked response."""
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "resource": resource,
        "recommendation": recommendation,
    }
