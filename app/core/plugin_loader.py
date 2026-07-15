"""Plugin loader — runs discovered plugin agents and returns their reports.

Phase 3.5 execution layer. Two execution paths:

* ``llm_only`` / ``hybrid`` -> the shared ``run_llm_agent`` helper (no duplication
  of the invoke/parse/dedup/score pattern).
* ``rule_based`` -> a Python adapter registered in ``RULE_BASED_ADAPTERS``. This
  is how deterministic plugins (the compliance agent) execute without an LLM and
  reuse existing Phase 3.3 logic verbatim.

Every plugin runs in isolation: a discovery error, missing adapter, or runtime
exception is logged and yields no report, never breaking the pipeline. Plugins
run sequentially to respect the local-LLM single-stream constraint.
"""

import logging
from typing import Awaitable, Callable

from app.core.llm_agent import run_llm_agent
from app.core.plugin_registry import PluginAgent, discover_plugins
from app.models import AgentReport, AnalysisReport, Finding, Severity

logger = logging.getLogger(__name__)

# A rule_based adapter is called with the already-computed core agent reports and
# the parsed resources, and returns an AgentReport (or None to skip).
RuleBasedAdapter = Callable[
    [list[AgentReport], dict, list], Awaitable[AgentReport | None]
]


# --------------------------------------------------------------------------- #
# Compliance plugin adapter (first plugin; reuses Phase 3.3 logic)
# --------------------------------------------------------------------------- #
async def _compliance_adapter(
    agent_reports: list[AgentReport],
    k8s_resources: dict,
    tf_resources: list,
) -> AgentReport | None:
    """Wrap the existing compliance scorecard into an ``AgentReport``.

    Reuses ``app/core/compliance.py`` end to end — no LLM, no re-derivation.
    Score = mean of per-framework ``score_pct`` (100.0 when no framework applies,
    so a clean upload is never penalized). Findings summarize failed controls.
    """
    # Imported lazily so importing the loader never forces the compliance module.
    from app.core.compliance import (
        compute_compliance_scorecard,
        enrich_findings_with_compliance,
    )

    # Build a shell report from the core agent findings so compliance can read
    # (and enrich) their compliance_controls. overall_score is irrelevant here.
    shell = AnalysisReport(
        agent_reports=agent_reports,
        overall_score=0.0,
        executive_summary="",
        risk_summary="",
    )
    enrich_findings_with_compliance(shell)
    scorecard = compute_compliance_scorecard(shell, tf_resources=tf_resources)

    if not scorecard.frameworks:
        # Nothing to assess for this upload — neutral, non-penalizing report.
        return AgentReport(
            agent_name="Compliance Agent",
            findings=[],
            summary="No compliance framework applies to this infrastructure.",
            score=100.0,
        )

    score = round(
        sum(fw.score_pct for fw in scorecard.frameworks) / len(scorecard.frameworks), 1
    )

    findings: list[Finding] = []
    for fw in scorecard.frameworks:
        if fw.controls_failed:
            findings.append(Finding(
                agent="Compliance Agent",
                category="compliance-gap",
                # Severity scales with how much of the framework is failing.
                severity=(
                    Severity.HIGH if fw.score_pct < 50
                    else Severity.MEDIUM if fw.score_pct < 90
                    else Severity.LOW
                ),
                title=f"{fw.framework_name}: {len(fw.controls_failed)} control(s) failing",
                description=(
                    f"{fw.framework_name} (v{fw.version}) compliance is "
                    f"{fw.score_pct}% — failing controls: "
                    f"{', '.join(fw.controls_failed)}."
                ),
                resource=fw.framework_id,
                recommendation=(
                    "Remediate the findings mapped to these controls to raise the "
                    f"{fw.framework_name} compliance score."
                ),
            ))

    summary = (
        f"Assessed {len(scorecard.frameworks)} framework(s); "
        f"mean compliance {score}%."
    )
    return AgentReport(
        agent_name="Compliance Agent",
        findings=findings,
        summary=summary,
        score=float(score),
    )


# Registry of rule_based plugin adapters, keyed by plugin name (skill stem).
RULE_BASED_ADAPTERS: dict[str, RuleBasedAdapter] = {
    "compliance": _compliance_adapter,
}


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
async def run_plugin(
    plugin: PluginAgent,
    file_contents: dict[str, str],
    agent_reports: list[AgentReport],
    k8s_resources: dict,
    tf_resources: list,
) -> AgentReport | None:
    """Run a single plugin agent and return its report (or None if skipped)."""
    try:
        if plugin.agent_type == "rule_based":
            adapter = RULE_BASED_ADAPTERS.get(plugin.name)
            if adapter is None:
                logger.warning(
                    "rule_based plugin '%s' has no registered adapter; skipping.",
                    plugin.name,
                )
                return None
            return await adapter(agent_reports, k8s_resources, tf_resources)

        # llm_only / hybrid -> shared LLM helper using the skill body as prompt.
        return await run_llm_agent(
            agent_name=plugin.agent_name,
            system_prompt=plugin.prompt,
            file_contents=file_contents,
        )
    except Exception as e:  # noqa: BLE001 — isolate one plugin's failure
        logger.warning("Plugin '%s' raised during execution, skipping: %s", plugin.name, e)
        return None


async def run_all_plugins(
    file_contents: dict[str, str],
    agent_reports: list[AgentReport],
    k8s_resources: dict,
    tf_resources: list,
    plugins: list[PluginAgent] | None = None,
) -> list[AgentReport]:
    """Discover (or accept) plugins and run them sequentially.

    Returns the list of successful ``AgentReport``s (skipped/failed plugins are
    omitted). Empty list when no plugin is registered — the pipeline node then
    behaves as a pass-through.
    """
    plugins = discover_plugins() if plugins is None else plugins
    reports: list[AgentReport] = []
    for plugin in plugins:
        report = await run_plugin(
            plugin, file_contents, agent_reports, k8s_resources, tf_resources
        )
        if report is not None:
            logger.info(
                "Plugin '%s' done: %s/100, %d findings",
                plugin.name, report.score, len(report.findings),
            )
            reports.append(report)
    return reports
