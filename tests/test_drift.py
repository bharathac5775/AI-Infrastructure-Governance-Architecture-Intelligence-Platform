"""Tests for drift detection (Phase 3.2).

Reference: app/core/drift.py

These tests cover the pure-function drift logic. They do NOT touch ChromaDB
- baseline reports are constructed in memory and passed directly to compute_drift.

Critical semantics locked in here:
- Drift compares ONLY rule-based findings (category != 'ai-analysis').
  LLM-augmented findings are excluded because their text drifts across runs
  even when the input is identical.
- Score deltas are recomputed from rule-only findings using the production
  deductions table, NOT taken from report.overall_score / report.score
  directly (which include LLM findings).
- Re-running drift on two reports with the same rule findings but different
  LLM findings yields ZERO deltas and EMPTY introduced/resolved buckets.
"""
from __future__ import annotations

from app.core.drift import (
    _delta,
    _finding_signature,
    _is_deterministic,
    _rule_only_overall_score,
    _rule_only_score,
    compute_drift,
)
from app.models import (
    AgentReport,
    AnalysisReport,
    ArchitectureReview,
    Finding,
    Severity,
)

from tests.fixtures.findings import make_finding


# ---------------------------------------------------------------------------
# Builder helper: build a full AnalysisReport in memory for drift tests
# ---------------------------------------------------------------------------


def _full_report(
    report_id: str,
    findings_by_agent: dict[str, list[Finding]] | None = None,
    overall: float = 80.0,
    arch_score: float | None = None,
    timestamp: str = "2026-01-01T00:00:00",
    bundle_fingerprint: str = "",
    agent_score: float = 80.0,
) -> AnalysisReport:
    """Build a full AnalysisReport. agent_score is what AgentReport.score is set
    to — drift no longer reads this directly, but it's required by Pydantic."""
    findings_by_agent = findings_by_agent or {}
    agent_reports = [
        AgentReport(agent_name=name, findings=fs, summary="ok", score=agent_score)
        for name, fs in findings_by_agent.items()
    ]
    arch = (
        ArchitectureReview(architecture_score=arch_score, summary="ok")
        if arch_score is not None
        else None
    )
    return AnalysisReport(
        report_id=report_id,
        timestamp=timestamp,
        files_analyzed=["main.tf"],
        agent_reports=agent_reports,
        architecture_review=arch,
        overall_score=overall,
        executive_summary="",
        risk_summary="",
        bundle_fingerprint=bundle_fingerprint,
    )


def _llm_finding(**kwargs) -> Finding:
    """Helper: build an LLM-augmented finding (category='ai-analysis')."""
    kwargs.setdefault("category", "ai-analysis")
    return make_finding(**kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestIsDeterministic:
    def test_rule_finding_is_deterministic(self):
        f = make_finding(category="iam")
        assert _is_deterministic(f) is True

    def test_ai_analysis_finding_is_not_deterministic(self):
        f = make_finding(category="ai-analysis")
        assert _is_deterministic(f) is False


class TestFindingSignature:
    def test_signature_match_ignores_severity_and_description(self):
        a = make_finding(
            agent="Security Agent", category="iam",
            severity=Severity.HIGH, title="Wildcard policy",
            description="version 1", resource="aws_iam_policy.bad",
        )
        b = make_finding(
            agent="Security Agent", category="iam",
            severity=Severity.CRITICAL, title="Wildcard policy",
            description="completely different wording", resource="aws_iam_policy.bad",
        )
        assert _finding_signature(a) == _finding_signature(b)

    def test_signature_breaks_on_resource_change(self):
        a = make_finding(category="iam", title="Wildcard policy", resource="aws_iam_policy.x")
        b = make_finding(category="iam", title="Wildcard policy", resource="aws_iam_policy.y")
        assert _finding_signature(a) != _finding_signature(b)

    def test_signature_breaks_on_title_change(self):
        a = make_finding(category="iam", title="Wildcard policy", resource="r1")
        b = make_finding(category="iam", title="Different title", resource="r1")
        assert _finding_signature(a) != _finding_signature(b)


class TestDeltaHelper:
    def test_delta_basic(self):
        assert _delta(70.0, 85.0) == 15.0

    def test_delta_negative(self):
        assert _delta(85.0, 70.0) == -15.0

    def test_delta_none_propagates(self):
        assert _delta(None, 80.0) is None
        assert _delta(70.0, None) is None
        assert _delta(None, None) is None

    def test_delta_rounds_to_one_decimal(self):
        assert _delta(70.0, 85.4444) == 15.4
        assert _delta(70.0, 85.0001) == 15.0


class TestRuleOnlyScore:
    def test_no_findings_returns_100(self):
        rep = _full_report("a", {"Security Agent": []})
        assert _rule_only_score(rep, "security") == 100.0

    def test_high_finding_deducts_10(self):
        f = make_finding(severity=Severity.HIGH, category="iam")
        rep = _full_report("a", {"Security Agent": [f]})
        assert _rule_only_score(rep, "security") == 90.0

    def test_ai_analysis_findings_excluded(self):
        """The whole point of the fix: LLM findings don't affect drift score."""
        rule_finding = make_finding(severity=Severity.HIGH, category="iam")
        llm_finding = _llm_finding(severity=Severity.HIGH)
        rep = _full_report("a", {"Security Agent": [rule_finding, llm_finding]})
        # Only the rule finding deducts: 100 - 10 = 90
        assert _rule_only_score(rep, "security") == 90.0

    def test_missing_agent_returns_none(self):
        rep = _full_report("a", {"Security Agent": []})
        assert _rule_only_score(rep, "reliability") is None

    def test_score_floored_at_zero(self):
        # 100 - 10 critical (20 each) = -100, floored at 0
        findings = [make_finding(severity=Severity.CRITICAL, category="iam") for _ in range(10)]
        rep = _full_report("a", {"Security Agent": findings})
        assert _rule_only_score(rep, "security") == 0.0


class TestRuleOnlyOverallScore:
    def test_three_clean_agents_returns_100(self):
        rep = _full_report("a", {
            "Security Agent": [],
            "Reliability Agent": [],
            "Cost Agent": [],
        })
        assert _rule_only_overall_score(rep) == 100.0

    def test_security_finding_drags_overall_down(self):
        f = make_finding(severity=Severity.HIGH, category="iam")
        rep = _full_report("a", {
            "Security Agent": [f],          # rule-only score: 90
            "Reliability Agent": [],         # 100
            "Cost Agent": [],                # 100
        })
        # weights: 0.34/0.30/0.21, total 0.85
        # weighted = 90*0.34 + 100*0.30 + 100*0.21 = 30.6 + 30.0 + 21.0 = 81.6
        # 81.6 / 0.85 = 96.0
        assert _rule_only_overall_score(rep) == 96.0


# ---------------------------------------------------------------------------
# compute_drift — finding bucketing
# ---------------------------------------------------------------------------


class TestComputeDriftFindingBuckets:
    def test_introduced_resolved_persisting_buckets(self):
        common = make_finding(category="iam", title="Wildcard policy", resource="r1")
        only_baseline = make_finding(category="network", title="Open SG", resource="sg1")
        only_current = make_finding(
            agent="Reliability Agent", category="probes",
            title="No probes", resource="dep1",
        )

        baseline = _full_report("a", {"Security Agent": [common, only_baseline]})
        current = _full_report("b", {
            "Security Agent": [common],
            "Reliability Agent": [only_current],
        })

        d = compute_drift(baseline, current)
        intro_titles = {x["title"] for x in d["findings_introduced"]}
        res_titles = {x["title"] for x in d["findings_resolved"]}
        pers_titles = {x["title"] for x in d["findings_persisting"]}

        assert intro_titles == {"No probes"}
        assert res_titles == {"Open SG"}
        assert pers_titles == {"Wildcard policy"}

    def test_ai_analysis_findings_excluded_from_all_buckets(self):
        """Critical regression test: LLM findings must not appear in any bucket.

        This is the bug from the original Phase 3.2 implementation. Re-uploading
        an identical file produced phantom 'introduced' and 'resolved' findings
        because the LLM emitted slightly different titles each run.
        """
        rule_finding = make_finding(category="iam", title="Wildcard", resource="r1")

        # Each report has the SAME rule finding but DIFFERENT LLM findings
        # (simulating the noise we see in production).
        baseline_llm = _llm_finding(title="S3 Versioning Status", resource="aws_s3.x")
        current_llm = _llm_finding(title="S3 Versioning Suspended", resource="aws_s3.x")

        baseline = _full_report("a", {"Security Agent": [rule_finding, baseline_llm]})
        current = _full_report("b", {"Security Agent": [rule_finding, current_llm]})

        d = compute_drift(baseline, current)
        # No phantom drift from LLM noise:
        assert d["findings_introduced"] == []
        assert d["findings_resolved"] == []
        # Rule finding persists, LLM findings excluded entirely:
        assert len(d["findings_persisting"]) == 1
        assert d["findings_persisting"][0]["title"] == "Wildcard"

    def test_severity_change_appears_as_persisting(self):
        baseline_finding = make_finding(
            category="iam", title="T1", resource="r1", severity=Severity.MEDIUM,
        )
        current_finding = make_finding(
            category="iam", title="T1", resource="r1", severity=Severity.HIGH,
        )
        baseline = _full_report("a", {"Security Agent": [baseline_finding]})
        current = _full_report("b", {"Security Agent": [current_finding]})
        d = compute_drift(baseline, current)
        assert len(d["findings_persisting"]) == 1
        assert d["findings_introduced"] == []
        assert d["findings_resolved"] == []

    def test_empty_baseline_all_findings_introduced(self):
        f1 = make_finding(category="iam", title="T1", resource="r1")
        f2 = make_finding(agent="Reliability Agent", category="probes", title="T2", resource="r2")
        baseline = _full_report("a", {})
        current = _full_report("b", {
            "Security Agent": [f1],
            "Reliability Agent": [f2],
        })
        d = compute_drift(baseline, current)
        assert len(d["findings_introduced"]) == 2
        assert len(d["findings_resolved"]) == 0
        assert len(d["findings_persisting"]) == 0

    def test_empty_current_all_findings_resolved(self):
        f1 = make_finding(category="iam", title="T1", resource="r1")
        baseline = _full_report("a", {"Security Agent": [f1]})
        current = _full_report("b", {})
        d = compute_drift(baseline, current)
        assert len(d["findings_introduced"]) == 0
        assert len(d["findings_resolved"]) == 1
        assert len(d["findings_persisting"]) == 0


# ---------------------------------------------------------------------------
# compute_drift — score deltas (rule-only)
# ---------------------------------------------------------------------------


class TestComputeDriftScoreDeltas:
    def test_zero_deltas_for_identical_rule_findings(self):
        """Phase 3.2 fix: identical rule findings produce zero deltas, even if
        LLM findings differ (which they will in production)."""
        rule_finding = make_finding(severity=Severity.HIGH, category="iam")
        baseline = _full_report("a", {
            "Security Agent": [rule_finding, _llm_finding(title="ghost-A")],
            "Reliability Agent": [],
            "Cost Agent": [],
        })
        current = _full_report("b", {
            "Security Agent": [rule_finding, _llm_finding(title="ghost-B-different")],
            "Reliability Agent": [],
            "Cost Agent": [],
        })
        d = compute_drift(baseline, current)
        assert d["score_deltas"]["security"] == 0.0
        assert d["score_deltas"]["reliability"] == 0.0
        assert d["score_deltas"]["cost"] == 0.0
        assert d["score_deltas"]["overall"] == 0.0

    def test_resolved_high_finding_improves_score(self):
        rule_finding = make_finding(severity=Severity.HIGH, category="iam")
        baseline = _full_report("a", {"Security Agent": [rule_finding]})
        current = _full_report("b", {"Security Agent": []})
        d = compute_drift(baseline, current)
        # Security: 90 -> 100 = +10
        assert d["score_deltas"]["security"] == 10.0

    def test_introduced_critical_finding_drops_score(self):
        critical = make_finding(severity=Severity.CRITICAL, category="iam")
        baseline = _full_report("a", {"Security Agent": []})
        current = _full_report("b", {"Security Agent": [critical]})
        d = compute_drift(baseline, current)
        # Security: 100 -> 80 = -20
        assert d["score_deltas"]["security"] == -20.0

    def test_overall_score_delta_uses_rule_only_weighted_average(self):
        rule_high = make_finding(severity=Severity.HIGH, category="iam")
        baseline = _full_report("a", {
            "Security Agent": [rule_high],
            "Reliability Agent": [],
            "Cost Agent": [],
        })
        current = _full_report("b", {
            "Security Agent": [],
            "Reliability Agent": [],
            "Cost Agent": [],
        })
        d = compute_drift(baseline, current)
        # baseline overall: 96.0, current overall: 100.0 → delta +4.0
        assert d["score_deltas"]["overall"] == 4.0

    def test_architecture_delta_when_both_present(self):
        baseline = _full_report("a", {}, arch_score=70.0)
        current = _full_report("b", {}, arch_score=85.0)
        d = compute_drift(baseline, current)
        assert d["score_deltas"]["architecture"] == 15.0

    def test_architecture_delta_none_when_baseline_missing(self):
        baseline = _full_report("a", {}, arch_score=None)
        current = _full_report("b", {}, arch_score=85.0)
        d = compute_drift(baseline, current)
        assert d["score_deltas"]["architecture"] is None

    def test_arch_noise_does_not_pollute_overall_delta(self):
        """Critical regression test: re-uploading an identical bundle, the
        architecture review's gap LIST often varies because it's LLM-generated.
        That noise must NOT appear in the overall delta — overall is the
        weighted average of rule-only AGENT scores, with architecture
        deliberately excluded.

        This was the residual bug after the first round of Phase 3.2 fixes:
        users still saw a non-zero overall delta even when all three agent
        deltas were zero, because architecture_score was leaking LLM-driven
        gap-count variation into the overall calculation.
        """
        rule_finding = make_finding(severity=Severity.HIGH, category="iam")
        # Both reports have IDENTICAL rule-based agent findings (so rule-only
        # agent scores are identical), but DIFFERENT architecture scores
        # (simulating LLM gap-list variation between runs).
        baseline = _full_report(
            "a",
            {
                "Security Agent": [rule_finding],
                "Reliability Agent": [],
                "Cost Agent": [],
            },
            arch_score=80.0,
        )
        current = _full_report(
            "b",
            {
                "Security Agent": [rule_finding],
                "Reliability Agent": [],
                "Cost Agent": [],
            },
            arch_score=70.0,  # ≠ baseline — simulates LLM noise
        )
        d = compute_drift(baseline, current)
        # All three agent deltas zero (rule findings identical):
        assert d["score_deltas"]["security"] == 0.0
        assert d["score_deltas"]["reliability"] == 0.0
        assert d["score_deltas"]["cost"] == 0.0
        # Overall MUST also be zero — arch noise must not leak in:
        assert d["score_deltas"]["overall"] == 0.0
        # Architecture delta is still surfaced separately (informational):
        assert d["score_deltas"]["architecture"] == -10.0


# ---------------------------------------------------------------------------
# compute_drift — severity summary
# ---------------------------------------------------------------------------


class TestSeveritySummary:
    def test_severity_summary_counts_introduced(self):
        high = make_finding(category="iam", title="T1", resource="r1", severity=Severity.HIGH)
        crit = make_finding(category="iam", title="T2", resource="r2", severity=Severity.CRITICAL)
        baseline = _full_report("a", {"Security Agent": []})
        current = _full_report("b", {"Security Agent": [high, crit]})
        d = compute_drift(baseline, current)
        assert d["severity_summary"]["introduced"]["high"] == 1
        assert d["severity_summary"]["introduced"]["critical"] == 1
        assert d["severity_summary"]["introduced"]["medium"] == 0

    def test_severity_summary_counts_resolved(self):
        high = make_finding(category="iam", title="T1", resource="r1", severity=Severity.HIGH)
        baseline = _full_report("a", {"Security Agent": [high]})
        current = _full_report("b", {"Security Agent": []})
        d = compute_drift(baseline, current)
        assert d["severity_summary"]["resolved"]["high"] == 1
        assert d["severity_summary"]["introduced"]["high"] == 0

    def test_ai_analysis_findings_not_counted_in_severity_summary(self):
        llm_high = _llm_finding(severity=Severity.HIGH, title="ghost")
        baseline = _full_report("a", {"Security Agent": []})
        current = _full_report("b", {"Security Agent": [llm_high]})
        d = compute_drift(baseline, current)
        # No rule finding introduced → all severity counts zero
        assert all(v == 0 for v in d["severity_summary"]["introduced"].values())


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestComputeDriftMetadata:
    def test_metadata_includes_report_ids_and_timestamps(self):
        baseline = _full_report("base-id", {}, timestamp="2026-01-01T00:00:00")
        current = _full_report("curr-id", {}, timestamp="2026-01-02T00:00:00")
        d = compute_drift(baseline, current)
        assert d["baseline"]["report_id"] == "base-id"
        assert d["baseline"]["timestamp"] == "2026-01-01T00:00:00"
        assert d["current"]["report_id"] == "curr-id"
        assert d["current"]["timestamp"] == "2026-01-02T00:00:00"
