"""Strict regression tests: run rule-based checks on each sample file and
assert deterministic scores match the pinned values in expected_scores.yaml.

This test is fully synchronous and fully deterministic — no LLM, no async,
no mocks. If a rule changes, exactly one number in expected_scores.yaml needs
to be updated.
"""
from __future__ import annotations

import json

import pytest

from app.agents.cost import run_cost_rules, run_terraform_cost_rules
from app.agents.reliability import run_reliability_rules, run_terraform_reliability_rules
from app.agents.security import (
    _detect_infra_type,
    run_security_rules,
    run_terraform_security_rules,
)
from app.core.report import calculate_overall_score
from app.models import AgentReport, Severity
from app.parsers.kubernetes import extract_k8s_resources, parse_kubernetes_yaml
from app.parsers.terraform import extract_tf_resources, parse_terraform

from tests.fixtures.scoring import compute_agent_score


def _parse_sample(filename: str, content: str) -> tuple[str, dict, list]:
    """Detect infra type and parse into (k8s_resources, tf_resources)."""
    infra_type = _detect_infra_type({filename: content})
    k8s_resources: dict = {}
    tf_resources: list = []
    if filename.endswith((".yaml", ".yml")):
        try:
            docs = parse_kubernetes_yaml(content)
            k8s_resources = extract_k8s_resources(docs)
        except Exception:
            pass
    elif filename.endswith((".tf", ".hcl")):
        try:
            parsed = parse_terraform(content)
            tf_resources = extract_tf_resources(parsed)
        except Exception:
            pass
    elif filename.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, dict) and data.get("apiVersion"):
                k8s_resources = extract_k8s_resources([data])
            elif isinstance(data, dict) and (data.get("resource") or data.get("terraform")):
                tf_resources = extract_tf_resources(data)
        except Exception:
            pass
    return infra_type, k8s_resources, tf_resources


def _run_rules(k8s_resources: dict, tf_resources: list) -> dict[str, list]:
    """Return {agent_name: list[Finding]} from running all 3 rule sets."""
    return {
        "Security Agent":
            run_security_rules(k8s_resources) + run_terraform_security_rules(tf_resources),
        "Reliability Agent":
            run_reliability_rules(k8s_resources) + run_terraform_reliability_rules(tf_resources),
        "Cost Agent":
            run_cost_rules(k8s_resources) + run_terraform_cost_rules(tf_resources),
    }


def _build_reports(findings_by_agent: dict[str, list]) -> list[AgentReport]:
    return [
        AgentReport(agent_name=agent, findings=fs, score=compute_agent_score(fs), summary="")
        for agent, fs in findings_by_agent.items()
    ]


# ---------------------------------------------------------------------------
# Bootstrapping helper — print scores for samples not yet in the manifest.
# Marked manual so it doesn't run in CI; invoke with:
#   pytest tests/test_samples_rules_only.py::test_dump_actual_scores -s --run-bootstrap
# Comment the skip below when bootstrapping the manifest.
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="bootstrap helper — un-skip to dump current scores")
def test_dump_actual_scores(sample_loader, expected_scores):
    """Print actual rules-only scores for every sample. Use to populate the manifest."""
    sample_files = list((sample_loader.__self__ if hasattr(sample_loader, "__self__")
                         else None) or [])
    # Read directory directly
    from pathlib import Path
    samples_dir = Path(__file__).parent.parent / "samples"
    print()
    for path in sorted(samples_dir.iterdir()):
        if path.is_dir() or path.suffix not in (".yaml", ".yml", ".tf", ".hcl", ".json"):
            continue
        content = path.read_text(encoding="utf-8")
        infra_type, k8s, tf = _parse_sample(path.name, content)
        if infra_type == "none":
            continue
        findings_by_agent = _run_rules(k8s, tf)
        reports = _build_reports(findings_by_agent)
        overall = calculate_overall_score(reports, architecture_review=None)
        per_agent = {r.agent_name: r.score for r in reports}
        counts = {r.agent_name: len(r.findings) for r in reports}
        print(f"{path.name:45s} type={infra_type:11s} overall={overall:5.1f} "
              f"per_agent={per_agent} counts={counts}")


# ---------------------------------------------------------------------------
# Pinned regression tests
# ---------------------------------------------------------------------------


def _all_samples_in_manifest(expected_scores: dict) -> list[str]:
    return list((expected_scores.get("samples") or {}).keys())


@pytest.fixture(params=[])  # populated dynamically in pytest_generate_tests
def sample_name(request):
    return request.param


def pytest_generate_tests(metafunc):
    """Parametrize the regression tests across every sample in the manifest."""
    if "sample_name" in metafunc.fixturenames:
        from tests.conftest import EXPECTED_SCORES_PATH
        import yaml as _yaml
        if EXPECTED_SCORES_PATH.exists():
            data = _yaml.safe_load(EXPECTED_SCORES_PATH.read_text()) or {}
            samples = list((data.get("samples") or {}).keys())
        else:
            samples = []
        metafunc.parametrize("sample_name", samples)


def test_sample_overall_score(sample_loader, expected_scores, sample_name):
    """For each manifest entry, assert overall_score within tolerance."""
    spec = expected_scores["samples"][sample_name]
    rules_only = spec.get("rules_only")
    if rules_only is None:
        pytest.skip(f"{sample_name} has no rules_only block")
    expected = rules_only["overall_score"]
    tol = rules_only.get("tolerance", 0.1)

    content = sample_loader(sample_name)
    infra_type, k8s, tf = _parse_sample(sample_name, content)
    expected_type = spec.get("infra_type")
    if expected_type:
        assert infra_type == expected_type, (
            f"{sample_name}: expected infra_type={expected_type}, got {infra_type}"
        )

    findings_by_agent = _run_rules(k8s, tf)
    reports = _build_reports(findings_by_agent)
    overall = calculate_overall_score(reports, architecture_review=None)

    assert abs(overall - expected) <= tol, (
        f"{sample_name}: rules-only overall_score {overall} differs from pinned {expected} "
        f"(tolerance {tol}). If intentional, update tests/expected_scores.yaml."
    )


def test_sample_agent_scores(sample_loader, expected_scores, sample_name):
    """Per-agent scores must match the manifest exactly (deterministic)."""
    spec = expected_scores["samples"][sample_name]
    rules_only = spec.get("rules_only", {})
    expected_agents = rules_only.get("agent_scores")
    if not expected_agents:
        pytest.skip(f"{sample_name} has no agent_scores block")

    content = sample_loader(sample_name)
    _, k8s, tf = _parse_sample(sample_name, content)
    findings_by_agent = _run_rules(k8s, tf)
    actual = {agent: compute_agent_score(fs) for agent, fs in findings_by_agent.items()}

    for agent, expected_score in expected_agents.items():
        assert actual[agent] == expected_score, (
            f"{sample_name}: {agent} score {actual[agent]} != pinned {expected_score}"
        )


def test_sample_must_have_findings(sample_loader, expected_scores, sample_name):
    """Findings listed in must_have_findings must be present in the result."""
    spec = expected_scores["samples"][sample_name]
    must_have = spec.get("must_have_findings", [])
    if not must_have:
        pytest.skip(f"{sample_name} has no must_have_findings")

    content = sample_loader(sample_name)
    _, k8s, tf = _parse_sample(sample_name, content)
    findings_by_agent = _run_rules(k8s, tf)

    for required in must_have:
        agent = required["agent"]
        substr = required["title_substring"].lower()
        all_titles = [f.title.lower() for f in findings_by_agent.get(agent, [])]
        assert any(substr in t for t in all_titles), (
            f"{sample_name}: expected finding in {agent} containing '{substr}', "
            f"got titles: {all_titles}"
        )


def test_sample_must_not_have_findings(sample_loader, expected_scores, sample_name):
    """Findings listed in must_not_have_findings must be absent (Phase 2 sentinels)."""
    spec = expected_scores["samples"][sample_name]
    must_not = spec.get("must_not_have_findings", [])
    if not must_not:
        pytest.skip(f"{sample_name} has no must_not_have_findings")

    content = sample_loader(sample_name)
    _, k8s, tf = _parse_sample(sample_name, content)
    findings_by_agent = _run_rules(k8s, tf)

    for forbidden in must_not:
        agent = forbidden["agent"]
        substr = forbidden["title_substring"].lower()
        all_titles = [f.title.lower() for f in findings_by_agent.get(agent, [])]
        matches = [t for t in all_titles if substr in t]
        assert not matches, (
            f"{sample_name}: forbidden finding in {agent} containing '{substr}' "
            f"was generated. Matches: {matches}"
        )
