"""Drift detection between successive analyses of the same infrastructure bundle.

Phase 3.2: identifies when a re-uploaded bundle has been analyzed before
(via filename-set bundle fingerprint), then computes finding-level + score-level
drift between the current scan and the most recent prior one.

Why this module ignores LLM-generated content entirely
======================================================
Rule-based findings are 100% deterministic — same input always produces the
same finding set. LLM-augmented findings (category == "ai-analysis") have
inherent run-to-run noise: the local Gemma model produces slightly different
titles, resources, and wording on every invocation, even at low temperature.
The architecture review is also LLM-driven — the gap LIST it emits varies
across runs even though the per-gap deduction math is deterministic.

If we included any of this in drift comparison, re-uploading an *identical*
file would surface phantom "introduced" / "resolved" findings AND phantom
score deltas. That defeats the entire purpose of drift detection.

So drift compares only the deterministic substrate:
- introduced/resolved/persisting buckets exclude LLM-augmented findings
- per-agent score deltas are recomputed from rule-only findings
- the OVERALL delta is a weighted average of the three rule-only agent
  scores (renormalized to 0.85 total weight, dropping architecture's 0.15
  slice). When all three agent deltas are zero, the overall is zero —
  always — regardless of architecture-review noise.
- the architecture delta is still SURFACED in score_deltas["architecture"]
  for users who want to see it, but it does not contribute to overall.

The agent-level score on the report itself still reflects rule + LLM findings
(unchanged), and LLM findings still appear in the report. Drift just sees
through the noise to the deterministic substrate.
"""
from __future__ import annotations

from typing import Optional

from app.core.store import find_by_bundle_fingerprint, get_report
from app.models import AnalysisReport, Finding, Severity


# LLM-augmented findings get this category in production. They're excluded from
# drift comparison because LLM output is non-deterministic across runs.
_LLM_FINDING_CATEGORY = "ai-analysis"

# Same deduction values as the agents' score calculation
# (security.py / reliability.py / cost.py — kept in sync via
# tests/test_scoring.py::TestSeverityDeductionsInSync).
_SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Per-dimension weights for overall score calculation
# (mirrors app/core/report.py::calculate_overall_score).
_DIMENSION_WEIGHTS = {
    "security": 0.34,
    "reliability": 0.30,
    "cost": 0.21,
    "architecture": 0.15,
}


def _is_deterministic(f: Finding) -> bool:
    """True if a finding is rule-based (deterministic) rather than LLM-augmented."""
    return f.category != _LLM_FINDING_CATEGORY


def _finding_signature(f: Finding) -> tuple[str, str, str, str]:
    """Stable identity for a finding across runs.

    Tuple of (agent, category, title, resource). Severity is NOT part of the
    signature because the same finding can be re-classified across LLM runs.
    Description is NOT included because LLM wording drifts across runs.
    """
    return (f.agent, f.category, f.title, f.resource)


def find_baseline(current: AnalysisReport) -> Optional[AnalysisReport]:
    """Return the most recent prior report with the same bundle_fingerprint.

    Returns None if:
    - the current report has no fingerprint (legacy reports)
    - no other report shares this fingerprint
    """
    if not current.bundle_fingerprint:
        return None
    matches = find_by_bundle_fingerprint(
        current.bundle_fingerprint, exclude_id=current.report_id
    )
    if not matches:
        return None
    # find_by_bundle_fingerprint returns sorted desc by timestamp.
    # Defensively prefer the first match whose timestamp predates current
    # (in case of clock skew, two near-simultaneous uploads, etc.).
    for m in matches:
        if m.get("timestamp", "") <= current.timestamp:
            return get_report(m["report_id"])
    # No predecessor found — return the most recent match anyway
    return get_report(matches[0]["report_id"])


def _delta(baseline_value: Optional[float], current_value: Optional[float]) -> Optional[float]:
    """Compute current minus baseline. Returns None if either side is missing."""
    if baseline_value is None or current_value is None:
        return None
    return round(current_value - baseline_value, 1)


def _agent_findings_by_prefix(report: AnalysisReport, prefix: str) -> list[Finding]:
    """Return rule-based findings only from the agent whose name starts with prefix."""
    for ar in report.agent_reports:
        if ar.agent_name.lower().startswith(prefix):
            return [f for f in ar.findings if _is_deterministic(f)]
    return []


def _score_from_findings(findings: list[Finding]) -> float:
    """Recompute an agent score from a list of findings using the deductions table.

    Mirrors the production agent scoring logic exactly. Used to derive a
    rule-only score for drift comparison.
    """
    score = 100.0
    for f in findings:
        score -= _SEVERITY_DEDUCTIONS.get(f.severity, 5)
    return max(0.0, score)


def _agent_has_data(report: AnalysisReport, prefix: str) -> bool:
    """True iff the report has an AgentReport with the given name prefix."""
    for ar in report.agent_reports:
        if ar.agent_name.lower().startswith(prefix):
            return True
    return False


def _rule_only_score(report: AnalysisReport, prefix: str) -> Optional[float]:
    """Return rule-only score for an agent, or None if the agent isn't in the report."""
    if not _agent_has_data(report, prefix):
        return None
    return _score_from_findings(_agent_findings_by_prefix(report, prefix))


def _rule_only_overall_score(report: AnalysisReport) -> float:
    """Recompute the overall score from rule-only per-agent scores.

    Architecture is INTENTIONALLY excluded from this calculation. The
    architecture review is LLM-driven (the LLM emits a list of gaps each
    run, and run-to-run variation in that list creates score noise even
    though the deduction math itself is deterministic). Including it here
    would leak that noise into the overall drift delta.

    Weights mirror app/core/report.py::calculate_overall_score for the three
    agent dimensions (0.34/0.30/0.21). Total renormalizes to 0.85 since the
    0.15 architecture slice is dropped — meaning a "perfect" agent posture
    yields overall=100 in this rule-only view, even if architecture has gaps.

    The architecture delta is still surfaced as a separate field in the
    drift response (see compute_drift's score_deltas["architecture"]) so
    users can see it; it just doesn't pollute the overall.
    """
    weighted = 0.0
    total_weight = 0.0
    for prefix in ("security", "reliability", "cost"):
        s = _rule_only_score(report, prefix)
        if s is not None:
            w = _DIMENSION_WEIGHTS[prefix]
            weighted += s * w
            total_weight += w
    return round(weighted / total_weight, 1) if total_weight > 0 else 0.0


def _all_deterministic_findings(report: AnalysisReport) -> list[Finding]:
    """Flatten findings across all agents, EXCLUDING LLM-augmented ones."""
    out: list[Finding] = []
    for ar in report.agent_reports:
        out.extend(f for f in ar.findings if _is_deterministic(f))
    return out


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in counts:
            counts[sev] += 1
    return counts


def compute_drift(baseline: AnalysisReport, current: AnalysisReport) -> dict:
    """Compute finding-level and score-level drift between two reports.

    All comparisons use only rule-based findings:
    - introduced / resolved / persisting buckets exclude LLM findings
    - per-agent score deltas use rule-only scores recomputed from findings
    - overall score delta uses rule-only weighted average

    This makes drift fully deterministic: re-uploading an identical bundle
    yields all-zero deltas and empty introduced/resolved buckets.
    """
    base_findings = _all_deterministic_findings(baseline)
    curr_findings = _all_deterministic_findings(current)

    base_sigs = {_finding_signature(f): f for f in base_findings}
    curr_sigs = {_finding_signature(f): f for f in curr_findings}

    introduced = [curr_sigs[s] for s in curr_sigs if s not in base_sigs]
    resolved = [base_sigs[s] for s in base_sigs if s not in curr_sigs]
    persisting = [curr_sigs[s] for s in curr_sigs if s in base_sigs]

    base_arch = (
        baseline.architecture_review.architecture_score
        if baseline.architecture_review
        else None
    )
    curr_arch = (
        current.architecture_review.architecture_score
        if current.architecture_review
        else None
    )

    return {
        "baseline": {"report_id": baseline.report_id, "timestamp": baseline.timestamp},
        "current": {"report_id": current.report_id, "timestamp": current.timestamp},
        "score_deltas": {
            "overall": _delta(
                _rule_only_overall_score(baseline),
                _rule_only_overall_score(current),
            ),
            "security": _delta(
                _rule_only_score(baseline, "security"),
                _rule_only_score(current, "security"),
            ),
            "reliability": _delta(
                _rule_only_score(baseline, "reliability"),
                _rule_only_score(current, "reliability"),
            ),
            "cost": _delta(
                _rule_only_score(baseline, "cost"),
                _rule_only_score(current, "cost"),
            ),
            "architecture": _delta(base_arch, curr_arch),
        },
        "findings_introduced": [f.model_dump() for f in introduced],
        "findings_resolved": [f.model_dump() for f in resolved],
        "findings_persisting": [f.model_dump() for f in persisting],
        "severity_summary": {
            "introduced": _severity_counts(introduced),
            "resolved": _severity_counts(resolved),
            "persisting": _severity_counts(persisting),
        },
    }


