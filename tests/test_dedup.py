"""Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup.

Reference code:
- app/core/dedup.py
- app/agents/architecture_reviewer.py:154-233
"""
from __future__ import annotations

from app.agents.architecture_reviewer import _dedup_cross_cutting_gaps
from app.core.dedup import extract_keywords, is_duplicate
from app.models import Severity

from tests.fixtures.findings import make_finding, make_gap, make_report


# ---------------------------------------------------------------------------
# extract_keywords
# ---------------------------------------------------------------------------


class TestExtractKeywords:
    def test_camelcase_split(self):
        kw = extract_keywords("HorizontalPodAutoscaler")
        assert "horizontal" in kw
        assert "pod" in kw
        assert "autoscaler" in kw

    def test_pascal_and_camel_mixed(self):
        kw = extract_keywords("PodDisruptionBudget runAsNonRoot")
        assert "pod" in kw
        assert "disruption" in kw
        assert "budget" in kw
        # runAsNonRoot splits to run/as/non/root; "run" is short enough to be filtered
        # only if it's <=2 chars or a stop word; it's neither so it stays.
        assert "root" in kw

    def test_stop_words_removed(self):
        kw = extract_keywords("missing the readiness probe and not having it")
        assert "missing" not in kw
        assert "the" not in kw
        assert "not" not in kw
        assert "and" not in kw
        assert "readiness" in kw
        assert "probe" in kw

    def test_synonym_expansion_password(self):
        kw = extract_keywords("password hardcoded in config")
        # password → secret, hardcoded → plaintext
        assert "password" in kw
        assert "secret" in kw
        assert "hardcoded" in kw
        assert "plaintext" in kw

    def test_synonym_hpa_expansion(self):
        kw = extract_keywords("HPA missing")
        assert "hpa" in kw
        assert "autoscaling" in kw  # synonym expansion

    def test_plural_to_singular(self):
        kw = extract_keywords("probes are missing")
        # plural→singular only direction
        assert "probe" in kw

    def test_distinct_probes_not_collapsed(self):
        liveness_kw = extract_keywords("Missing liveness probe")
        readiness_kw = extract_keywords("Missing readiness probe")
        # These keywords must NOT be in each other's set — different findings
        assert "liveness" in liveness_kw
        assert "liveness" not in readiness_kw
        assert "readiness" in readiness_kw
        assert "readiness" not in liveness_kw

    def test_short_words_filtered(self):
        kw = extract_keywords("a b cd is")
        # words of length <=2 dropped (the helper only keeps len > 2)
        assert "a" not in kw
        assert "b" not in kw
        assert "cd" not in kw

    def test_punctuation_stripped(self):
        kw = extract_keywords("config: missing! probes?")
        assert "config" in kw
        assert "probe" in kw

    def test_empty_string_returns_empty_set(self):
        assert extract_keywords("") == set()


# ---------------------------------------------------------------------------
# is_duplicate
# ---------------------------------------------------------------------------


class TestIsDuplicate:
    def test_three_keyword_overlap_is_duplicate(self):
        rule = make_finding(
            title="Missing readiness probe",
            description="Container app has no readiness probe configured.",
            category="probes",
        )
        # LLM finding shares: readiness, probe, container → 3 overlap
        llm = make_finding(
            title="Readiness probe absent on container",
            description="The container does not declare a readiness probe.",
        )
        assert is_duplicate(llm, [rule]) is True

    def test_low_overlap_not_duplicate(self):
        rule = make_finding(
            title="Privileged container",
            description="Container runs in privileged mode.",
            category="privileges",
        )
        llm = make_finding(
            title="Cost overrun in storage",
            description="Storage costs exceed budget threshold.",
        )
        assert is_duplicate(llm, [rule]) is False

    def test_synonym_match_counts(self):
        rule = make_finding(
            title="Hardcoded secret",
            description="Plaintext password stored in environment variable.",
            category="secrets",
        )
        # llm uses "credential" (synonym of secret), "plaintext" matches directly
        llm = make_finding(
            title="Plaintext credential exposure",
            description="Password is hardcoded in environment.",
        )
        assert is_duplicate(llm, [rule]) is True

    def test_empty_llm_keywords_not_duplicate(self):
        # An LLM finding with no extractable keywords should never duplicate
        llm = make_finding(title="a", description="b")
        rule = make_finding(title="Privileged container", description="Container runs in privileged mode.")
        assert is_duplicate(llm, [rule]) is False

    def test_empty_rule_list_not_duplicate(self):
        llm = make_finding(title="Some serious finding here", description="Many words about issues.")
        assert is_duplicate(llm, []) is False


# ---------------------------------------------------------------------------
# _dedup_cross_cutting_gaps
#
# Reference: app/agents/architecture_reviewer.py:154-233
# Rules (applied in order):
#   1. No agent keyword match → kept
#   2. Bundle echo (≥80% coverage of gap keywords by union of matched-finding
#      keywords) → dropped
#   3. Multi-agent (2+) with <80% coverage AND severity ≤ best+1 → kept
#   4. Single-agent match with <80% coverage AND severity == best+1
#      AND gap text mentions 2+ domains → kept
# ---------------------------------------------------------------------------


class TestDedupCrossCuttingGaps:
    def test_empty_findings_returns_gaps_unchanged(self):
        gaps = [make_gap(title="Some gap")]
        # All three reports None → all_findings is empty
        result = _dedup_cross_cutting_gaps(gaps, None, None, None)
        assert result == gaps

    def test_no_agent_keyword_match_kept(self):
        # Gap is about something no agent flagged
        gap = make_gap(
            title="API gateway throttling missing",
            description="No edge-level rate limiter configured between clients and backend.",
            severity=Severity.MEDIUM,
        )
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Privileged container",
                    description="Container runs in privileged mode in deployment app.",
                )
            ],
        )
        result = _dedup_cross_cutting_gaps([gap], sec, None, None)
        assert len(result) == 1
        assert result[0].title == "API gateway throttling missing"

    def test_bundle_echo_dropped(self):
        # Gap text is fully covered by union of agent-finding keywords → bundle echo
        # Make the gap copy keywords from two different agents.
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Privileged container hostNetwork enabled",
                    description="Container runs privileged with hostNetwork true.",
                    severity=Severity.HIGH,
                )
            ],
        )
        rel = make_report(
            "Reliability Agent",
            findings=[
                make_finding(
                    title="Missing readiness probe",
                    description="Container has no readiness probe configured.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        # Gap restates both agents' keywords — bundle echo
        gap = make_gap(
            title="Privileged container with missing probe",
            description=(
                "Container runs privileged with hostNetwork true and "
                "has no readiness probe configured."
            ),
            severity=Severity.HIGH,
        )
        result = _dedup_cross_cutting_gaps([gap], sec, rel, None)
        assert len(result) == 0  # dropped as bundle echo

    def test_multi_agent_synthesis_kept_when_severity_within_plus_one(self):
        # Two agents flag distinct issues at MEDIUM. Gap synthesizes a HIGH
        # cross-cutting concern with NEW keywords (not bundle echo).
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="No network segmentation policy",
                    description="Pods communicate freely with no network segmentation policy in place.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        rel = make_report(
            "Reliability Agent",
            findings=[
                make_finding(
                    title="Single replica deployment",
                    description="Workload runs single replica only.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        # Gap shares 3+ kw with each (network segmentation policy / single replica)
        # but adds NEW keywords → not bundle echo.
        gap = make_gap(
            title="Combined network segmentation policy single replica concern",
            description=(
                "Network segmentation policy absent and workload runs single replica only. "
                "Tight coupling of these two posture decisions creates a multi-tier risk."
            ),
            severity=Severity.HIGH,  # +1 above MEDIUM agent floor
        )
        result = _dedup_cross_cutting_gaps([gap], sec, rel, None)
        assert len(result) == 1

    def test_multi_agent_severity_too_high_dropped(self):
        # Multi-agent match but gap claims CRITICAL when agents only said MEDIUM
        # → severity > best+1 → dropped
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Network segmentation issue",
                    description="No segmentation between tiers.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        rel = make_report(
            "Reliability Agent",
            findings=[
                make_finding(
                    title="Single replica deployment",
                    description="Workload runs single replica only.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        gap = make_gap(
            title="Combined segmentation replica blast radius zero trust",
            description=(
                "Critical posture: no segmentation, single replica, no zero trust controls."
            ),
            severity=Severity.CRITICAL,  # +2 above MEDIUM floor → drop
        )
        result = _dedup_cross_cutting_gaps([gap], sec, rel, None)
        assert len(result) == 0

    def test_single_agent_same_severity_dropped(self):
        # Pure echo: single agent already said this at the same severity.
        # The gap's keywords don't bundle-echo (uses fresh phrasing) but
        # severity didn't escalate → drop.
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Hardcoded password environment",
                    description="Database password stored as plain environment variable.",
                    severity=Severity.HIGH,
                )
            ],
        )
        # Gap has 3+ overlap (hardcoded/password/environment) with rule but
        # adds new word "rotation" so coverage stays under 80%.
        gap = make_gap(
            title="Hardcoded credential rotation strategy",
            description="Hardcoded password rotation strategy and lifecycle missing.",
            severity=Severity.HIGH,  # same as agent → drop
        )
        result = _dedup_cross_cutting_gaps([gap], sec, None, None)
        assert len(result) == 0

    def test_single_agent_escalation_with_two_domains_kept(self):
        # +1 escalation AND text mentions 2+ domains → kept
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Hardcoded password environment",
                    description="Database password stored as plaintext environment variable.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        gap = make_gap(
            title="Hardcoded credential rotation strategy",
            description=(
                "Hardcoded password environment lacks rotation lifecycle. "
                "This impacts both security posture and reliability of the service "
                "during credential rollover."
            ),
            severity=Severity.HIGH,  # +1 above agent
        )
        result = _dedup_cross_cutting_gaps([gap], sec, None, None)
        assert len(result) == 1

    def test_single_agent_escalation_only_one_domain_dropped(self):
        # +1 escalation BUT gap text mentions only 1 domain → dropped
        sec = make_report(
            "Security Agent",
            findings=[
                make_finding(
                    title="Hardcoded password environment",
                    description="Database password stored as plaintext environment variable.",
                    severity=Severity.MEDIUM,
                )
            ],
        )
        gap = make_gap(
            title="Hardcoded credential rotation lifecycle",
            description="Hardcoded password environment has no rotation lifecycle policy.",
            severity=Severity.HIGH,
        )
        result = _dedup_cross_cutting_gaps([gap], sec, None, None)
        assert len(result) == 0
