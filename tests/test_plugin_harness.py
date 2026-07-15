"""Tests for the Phase 3.5 plugin harness.

Covers:
- Registry discovery gate (frontmatter must declare agent_type + weight).
- Core-agent exclusion (tagged core skills never register as runtime plugins).
- Compliance registers as exactly one rule_based plugin.
- Scoring: zero-plugin invariance + additive/normalized with a plugin present.
- Plugin loader execution: llm_only via shared helper, rule_based via adapter,
  graceful skip when a rule_based adapter is missing.
- Compliance adapter produces a valid AgentReport.

Reference code:
- app/core/plugin_registry.py::discover_plugins / PluginAgent / CORE_AGENTS
- app/core/plugin_loader.py::run_all_plugins / run_plugin / _compliance_adapter
- app/core/report.py::calculate_overall_score (plugin_reports param)
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.plugin_registry import (
    CORE_AGENTS,
    PluginAgent,
    discover_plugins,
)
from app.core.plugin_loader import run_all_plugins, run_plugin
from app.core.report import calculate_overall_score
from app.models import AgentReport, Finding, Severity

from tests.fixtures.findings import make_report


# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_only_compliance_registers_from_real_skills(self):
        """The real skills/ dir must yield exactly the compliance plugin.

        Core agent skills carry agent_type/weight frontmatter (migration) but are
        excluded, so they must NOT appear as runtime plugins.
        """
        plugins = discover_plugins()
        names = {p.name for p in plugins}
        assert names == {"compliance"}, f"unexpected plugins: {names}"

    def test_compliance_is_rule_based(self):
        (compliance,) = [p for p in discover_plugins() if p.name == "compliance"]
        assert compliance.agent_type == "rule_based"
        assert compliance.agent_name == "Compliance Agent"
        assert 0.0 < compliance.weight <= 1.0

    def test_core_agents_excluded_even_when_tagged(self):
        """No discovered plugin maps to a hardcoded core agent."""
        for p in discover_plugins():
            # PluginAgent doesn't retain the raw `agent` slug, but the exclusion
            # set is keyed on it; assert via name mapping instead.
            assert p.name not in {
                "security-kubernetes", "security-terraform",
                "reliability-kubernetes", "reliability-terraform",
                "cost-kubernetes", "cost-terraform",
                "architecture-reviewer", "supervisor",
                "remediator-k8s", "remediator-tf",
            }

    def test_skill_without_frontmatter_is_not_a_plugin(self, tmp_path: Path):
        """A skill lacking agent_type/weight is ignored by discovery."""
        skill = tmp_path / "plain.md"
        skill.write_text(
            "---\nname: plain\nagent: plain\ninfra_type: all\n---\nBody.\n",
            encoding="utf-8",
        )
        assert discover_plugins(skills_dir=tmp_path) == []

    def test_partial_frontmatter_is_not_a_plugin(self, tmp_path: Path):
        """agent_type without weight (or vice versa) does not register."""
        (tmp_path / "a.md").write_text(
            "---\nname: a\nagent: a\nagent_type: llm_only\n---\nBody.\n", encoding="utf-8"
        )
        (tmp_path / "b.md").write_text(
            "---\nname: b\nagent: b\nweight: 0.1\n---\nBody.\n", encoding="utf-8"
        )
        assert discover_plugins(skills_dir=tmp_path) == []

    def test_valid_llm_plugin_registers(self, tmp_path: Path):
        (tmp_path / "extra.md").write_text(
            "---\nname: extra\nagent: extra\nagent_type: llm_only\nweight: 0.05\n---\n"
            "Do a custom analysis.\n",
            encoding="utf-8",
        )
        plugins = discover_plugins(skills_dir=tmp_path)
        assert len(plugins) == 1
        assert plugins[0].agent_type == "llm_only"
        assert plugins[0].weight == 0.05
        assert plugins[0].prompt.strip() == "Do a custom analysis."

    def test_bad_agent_type_skipped_not_raised(self, tmp_path: Path):
        (tmp_path / "bad.md").write_text(
            "---\nname: bad\nagent: bad\nagent_type: wizardry\nweight: 0.1\n---\nBody.\n",
            encoding="utf-8",
        )
        # Must not raise; simply skipped.
        assert discover_plugins(skills_dir=tmp_path) == []

    def test_out_of_range_weight_skipped(self, tmp_path: Path):
        (tmp_path / "heavy.md").write_text(
            "---\nname: heavy\nagent: heavy\nagent_type: hybrid\nweight: 5\n---\nBody.\n",
            encoding="utf-8",
        )
        assert discover_plugins(skills_dir=tmp_path) == []


# ---------------------------------------------------------------------------
# PluginAgent model validation
# ---------------------------------------------------------------------------


class TestPluginAgentModel:
    def test_rejects_unknown_agent_type(self):
        with pytest.raises(ValidationError):
            PluginAgent(
                name="x", agent_name="X", agent_type="nope",
                weight=0.1, skill_name="x",
            )

    def test_rejects_nonpositive_weight(self):
        with pytest.raises(ValidationError):
            PluginAgent(
                name="x", agent_name="X", agent_type="hybrid",
                weight=0.0, skill_name="x",
            )

    def test_coerces_string_weight(self):
        p = PluginAgent(
            name="x", agent_name="X", agent_type="hybrid",
            weight="0.15", skill_name="x",
        )
        assert p.weight == 0.15

    def test_core_agents_set_contents(self):
        assert {"security", "reliability", "cost", "architecture-reviewer"} <= CORE_AGENTS


# ---------------------------------------------------------------------------
# Scoring — zero-plugin invariance + additive/normalized
# ---------------------------------------------------------------------------


class TestScoringWithPlugins:
    def _core(self):
        return [
            make_report("Security Agent", score=80.0),
            make_report("Reliability Agent", score=90.0),
            make_report("Cost Agent", score=100.0),
        ]

    def test_empty_plugin_reports_is_identical_to_no_arg(self):
        core = self._core()
        baseline = calculate_overall_score(core)
        assert calculate_overall_score(core, plugin_reports=[]) == baseline
        assert calculate_overall_score(core, plugin_reports=None) == baseline
        # Sanity: baseline is the historically asserted value.
        assert baseline == 88.5

    def test_plugin_joins_normalized_pool(self):
        core = self._core()
        plugin = make_report("Compliance Agent", score=50.0)
        # weighted = 80*.34 + 90*.30 + 100*.21 + 50*.10 = 27.2+27+21+5 = 80.2
        # total = 0.85 + 0.10 = 0.95 ; 80.2/0.95 = 84.421... -> 84.4
        result = calculate_overall_score(core, plugin_reports=[(plugin, 0.10)])
        assert result == 84.4

    def test_zero_weight_plugin_ignored(self):
        core = self._core()
        plugin = make_report("Compliance Agent", score=0.0)
        assert calculate_overall_score(core, plugin_reports=[(plugin, 0.0)]) == \
            calculate_overall_score(core)


# ---------------------------------------------------------------------------
# Plugin loader execution
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestPluginExecution:
    def test_compliance_adapter_returns_valid_report(self):
        """The compliance plugin runs against core findings and yields a report."""
        sec = AgentReport(
            agent_name="Security Agent",
            findings=[Finding(
                agent="Security Agent", category="privileged-container",
                severity=Severity.HIGH, title="Privileged container",
                description="", resource="Kind/Pod:x", recommendation="",
            )],
            summary="", score=90.0,
        )
        (compliance,) = [p for p in discover_plugins() if p.name == "compliance"]
        report = _run(run_plugin(
            compliance,
            file_contents={"pod.yaml": "kind: Pod\n"},
            agent_reports=[sec],
            k8s_resources={},
            tf_resources=[],
        ))
        assert report is not None
        assert report.agent_name == "Compliance Agent"
        assert 0.0 <= report.score <= 100.0

    def test_compliance_no_framework_scores_100(self):
        """A report with no applicable framework is not penalized."""
        (compliance,) = [p for p in discover_plugins() if p.name == "compliance"]
        report = _run(run_plugin(
            compliance,
            file_contents={"empty.txt": "nothing"},
            agent_reports=[],
            k8s_resources={},
            tf_resources=[],
        ))
        assert report is not None
        assert report.score == 100.0
        assert report.findings == []

    def test_missing_adapter_is_skipped(self, tmp_path: Path):
        """A rule_based plugin with no registered adapter returns None (skipped)."""
        plugin = PluginAgent(
            name="ghost", agent_name="Ghost Agent", agent_type="rule_based",
            weight=0.1, skill_name="ghost",
        )
        result = _run(run_plugin(
            plugin, file_contents={}, agent_reports=[],
            k8s_resources={}, tf_resources=[],
        ))
        assert result is None

    def test_run_all_plugins_empty_registry(self, tmp_path: Path):
        """No skills -> no reports (pass-through behavior)."""
        empty = discover_plugins(skills_dir=tmp_path)
        reports = _run(run_all_plugins(
            file_contents={}, agent_reports=[], k8s_resources={},
            tf_resources=[], plugins=empty,
        ))
        assert reports == []
