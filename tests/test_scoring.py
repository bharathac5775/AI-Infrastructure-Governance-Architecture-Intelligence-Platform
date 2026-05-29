"""Tests for scoring math.

Reference code:
- app/core/report.py::calculate_overall_score (weights 0.34/0.30/0.21/0.15)
- app/agents/architecture_reviewer.py::_calculate_architecture_score
"""
from __future__ import annotations

import pytest

from app.agents.architecture_reviewer import _calculate_architecture_score
from app.core.report import calculate_overall_score
from app.models import ArchitectureReview, Severity

from tests.fixtures.findings import make_gap, make_report


# ---------------------------------------------------------------------------
# calculate_overall_score
#
# Weights: Security 0.34, Reliability 0.30, Cost 0.21, Architecture 0.15
# Unknown agent: 0.28 default. Result is round(weighted/total_weight, 1).
# ---------------------------------------------------------------------------


class TestCalculateOverallScore:
    def test_three_agents_only(self):
        sec = make_report("Security Agent", score=80.0)
        rel = make_report("Reliability Agent", score=90.0)
        cost = make_report("Cost Agent", score=100.0)
        # weighted = 80*0.34 + 90*0.30 + 100*0.21 = 27.2 + 27.0 + 21.0 = 75.2
        # total_weight = 0.85; 75.2/0.85 = 88.4705... → round → 88.5
        assert calculate_overall_score([sec, rel, cost]) == 88.5

    def test_with_architecture_review(self):
        sec = make_report("Security Agent", score=100.0)
        rel = make_report("Reliability Agent", score=100.0)
        cost = make_report("Cost Agent", score=100.0)
        arch = ArchitectureReview(architecture_score=100.0, summary="")
        # All 100 with 4-way weighting → 100
        assert calculate_overall_score([sec, rel, cost], arch) == 100.0

    def test_architecture_drags_down(self):
        sec = make_report("Security Agent", score=100.0)
        rel = make_report("Reliability Agent", score=100.0)
        cost = make_report("Cost Agent", score=100.0)
        arch = ArchitectureReview(architecture_score=0.0, summary="")
        # weighted = 34 + 30 + 21 + 0 = 85; total = 1.0; result = 85.0
        assert calculate_overall_score([sec, rel, cost], arch) == 85.0

    def test_empty_reports_returns_zero(self):
        assert calculate_overall_score([]) == 0.0

    def test_unknown_agent_uses_default_weight(self):
        rep = make_report("Mystery Agent", score=50.0)
        # weighted = 50*0.28 = 14; total = 0.28; result = 14/0.28 = 50.0
        assert calculate_overall_score([rep]) == 50.0

    def test_single_known_agent(self):
        sec = make_report("Security Agent", score=72.0)
        # weighted = 72*0.34 = 24.48; total = 0.34; 24.48/0.34 = 72.0
        assert calculate_overall_score([sec]) == 72.0

    def test_rounding_to_one_decimal(self):
        sec = make_report("Security Agent", score=33.3333)
        rel = make_report("Reliability Agent", score=66.6666)
        cost = make_report("Cost Agent", score=99.9999)
        result = calculate_overall_score([sec, rel, cost])
        # Result should be exactly one decimal place
        assert result == round(result, 1)


# ---------------------------------------------------------------------------
# _calculate_architecture_score
#
# Deduction per gap: critical=25, high=15, medium=8, low=3.
# Capped at average of agent_scores (when provided).
# Floored at 0.
# ---------------------------------------------------------------------------


class TestArchitectureScore:
    def test_no_gaps_no_agent_scores_returns_100(self):
        assert _calculate_architecture_score(gaps=[], agent_scores=None) == 100.0

    def test_no_gaps_capped_by_agent_average(self):
        # Architecture cannot claim perfection when agents found issues
        score = _calculate_architecture_score(gaps=[], agent_scores=[80.0, 90.0])
        assert score == 85.0

    def test_critical_gap_deducts_25(self):
        gap = make_gap(severity=Severity.CRITICAL)
        assert _calculate_architecture_score([gap]) == 75.0

    def test_high_gap_deducts_15(self):
        gap = make_gap(severity=Severity.HIGH)
        assert _calculate_architecture_score([gap]) == 85.0

    def test_medium_gap_deducts_8(self):
        gap = make_gap(severity=Severity.MEDIUM)
        assert _calculate_architecture_score([gap]) == 92.0

    def test_low_gap_deducts_3(self):
        gap = make_gap(severity=Severity.LOW)
        assert _calculate_architecture_score([gap]) == 97.0

    def test_multiple_gaps_stack(self):
        gaps = [
            make_gap(severity=Severity.HIGH),    # -15
            make_gap(severity=Severity.MEDIUM),  # -8
            make_gap(severity=Severity.LOW),     # -3
        ]
        assert _calculate_architecture_score(gaps) == 74.0

    def test_score_floored_at_zero(self):
        gaps = [make_gap(severity=Severity.CRITICAL) for _ in range(10)]
        # 100 - 250 → floored at 0
        assert _calculate_architecture_score(gaps) == 0.0

    def test_cap_overrides_when_agents_low(self):
        # Without cap: 97. With agent_avg=55: cap forces score down to 55.
        gap = make_gap(severity=Severity.LOW)
        score = _calculate_architecture_score([gap], agent_scores=[50.0, 60.0])
        assert score == 55.0

    def test_cap_does_not_raise_score(self):
        # If gap-deduction score is already lower than agent_avg, cap doesn't apply
        gaps = [make_gap(severity=Severity.CRITICAL) for _ in range(2)]  # 100-50=50
        score = _calculate_architecture_score(gaps, agent_scores=[90.0, 100.0])
        # min(50, 95) = 50
        assert score == 50.0

    def test_returns_float(self):
        result = _calculate_architecture_score([])
        assert isinstance(result, float)


# ---------------------------------------------------------------------------
# Sync check: deduction table in tests/fixtures/scoring.py matches production
# ---------------------------------------------------------------------------


class TestSeverityDeductionsInSync:
    def test_table_matches_security_agent(self):
        """Guard against drift between the test-side deductions table and prod."""
        from tests.fixtures.scoring import SEVERITY_DEDUCTIONS

        # Read security.py and verify the dict literal matches.
        # This is brittle by design — if production changes the table, we want
        # this test to fail loudly so test fixtures stay in sync.
        from pathlib import Path
        sec_path = Path(__file__).parent.parent / "app" / "agents" / "security.py"
        text = sec_path.read_text(encoding="utf-8")
        for sev, val in SEVERITY_DEDUCTIONS.items():
            literal = f"Severity.{sev.name}: {val}"
            assert literal in text, f"Production no longer has '{literal}' — update tests/fixtures/scoring.py"
