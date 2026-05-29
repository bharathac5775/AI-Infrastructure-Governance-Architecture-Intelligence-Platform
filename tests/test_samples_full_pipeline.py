"""End-to-end integration tests: run the full pipeline (security/reliability/cost
agents → architecture review → supervisor) against each sample with mocked LLM,
and verify the overall scores still match expectations.

These tests exercise:
- parse_files_node dispatch (yaml/tf/json branching)
- LLM mock routing across all 5 agent call sites
- Architecture review wiring + dedup pipeline
- Supervisor synthesis
- Final overall_score calculation including the 0.15 architecture weight

Marker: @pytest.mark.integration / @pytest.mark.slow
"""
from __future__ import annotations

import pytest

from app.agents.supervisor import run_analysis


pytestmark = [pytest.mark.integration, pytest.mark.slow]


def pytest_generate_tests(metafunc):
    if "sample_name" in metafunc.fixturenames:
        from tests.conftest import EXPECTED_SCORES_PATH
        import yaml as _yaml
        if EXPECTED_SCORES_PATH.exists():
            data = _yaml.safe_load(EXPECTED_SCORES_PATH.read_text()) or {}
            samples = list((data.get("samples") or {}).keys())
        else:
            samples = []
        metafunc.parametrize("sample_name", samples)


async def test_sample_full_pipeline_overall_score(
    sample_loader, expected_scores, mock_llm, sample_name,
):
    """Full pipeline overall_score should be close to rules-only score.

    The architecture review adds a 0.15-weighted component that depends on
    the agent_score average (the cap rule). With LLM mock returning zero
    gaps, the architecture score equals the agent average → it slightly
    averages the overall toward the agent average.
    """
    spec = expected_scores["samples"][sample_name]
    full = spec.get("full_pipeline")
    rules_only = spec.get("rules_only")
    if not full and not rules_only:
        pytest.skip(f"{sample_name} has no expected scores")

    content = sample_loader(sample_name)
    report = await run_analysis({sample_name: content})

    # If the manifest has explicit full_pipeline expectations, use them.
    if full:
        expected = full["overall_score"]
        tol = full.get("tolerance", 1.0)
        assert abs(report.overall_score - expected) <= tol, (
            f"{sample_name}: full_pipeline overall_score {report.overall_score} "
            f"differs from pinned {expected} (tolerance {tol})"
        )
    else:
        # Otherwise, sanity check: full pipeline should be within 5 points of rules-only.
        # (Architecture review adds a 0.15-weighted dimension.)
        rules_expected = rules_only["overall_score"]
        assert abs(report.overall_score - rules_expected) <= 5.0, (
            f"{sample_name}: full_pipeline overall_score {report.overall_score} "
            f"diverged >5pts from rules-only baseline {rules_expected}"
        )


async def test_sample_full_pipeline_must_not_have_findings(
    sample_loader, expected_scores, mock_llm, sample_name,
):
    """Phase 2 sentinels must remain absent in the full pipeline too."""
    spec = expected_scores["samples"][sample_name]
    must_not = spec.get("must_not_have_findings", [])
    if not must_not:
        pytest.skip(f"{sample_name} has no must_not_have_findings")

    content = sample_loader(sample_name)
    report = await run_analysis({sample_name: content})

    # Build {agent_name: list[Finding]}
    by_agent: dict[str, list] = {}
    for r in report.agent_reports:
        by_agent[r.agent_name] = list(r.findings)

    for forbidden in must_not:
        agent = forbidden["agent"]
        substr = forbidden["title_substring"].lower()
        all_titles = [f.title.lower() for f in by_agent.get(agent, [])]
        matches = [t for t in all_titles if substr in t]
        assert not matches, (
            f"{sample_name}: forbidden finding in {agent} containing '{substr}' "
            f"appeared in full pipeline. Matches: {matches}"
        )
