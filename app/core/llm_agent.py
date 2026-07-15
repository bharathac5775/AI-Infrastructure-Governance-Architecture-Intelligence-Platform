"""Shared LLM-agent execution helper.

Phase 3.5 extracts the LLM invoke -> parse -> dedup -> score pattern that the
core agents (``security.py`` / ``reliability.py`` / ``cost.py``) each implement
inline. The plugin harness runs ``llm_only`` / ``hybrid`` plugin agents through
this single helper so the pattern lives in exactly one place going forward.

The core agents are intentionally NOT refactored to call this in Phase 3.5 —
their behavior and diffs stay minimal. New agents (plugins) use this helper.
"""

import json
import logging

from langchain_core.prompts import ChatPromptTemplate

from app.core.llm import get_llm
from app.core.dedup import is_duplicate as _is_duplicate
from app.models import AgentReport, Finding, Severity

logger = logging.getLogger(__name__)

# Single source of truth for severity -> score deduction. Mirrors the table used
# by the core agents (see app/agents/security.py). Kept here so plugin agents
# score on the exact same scale as the built-in agents.
SEVERITY_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def score_from_findings(findings: list[Finding]) -> float:
    """Compute a 0-100 agent score from findings via severity deductions.

    Identical formula to the core agents: 100 minus the summed deductions,
    floored at 0.
    """
    return float(max(0, 100 - sum(SEVERITY_DEDUCTIONS[f.severity] for f in findings)))


def _format_infra_content(file_contents: dict[str, str]) -> str:
    """Concatenate uploaded files into a single prompt-ready block.

    Matches the ``--- <fname> ---`` framing used by the core agents.
    """
    infra_content = ""
    for fname, content in file_contents.items():
        infra_content += f"\n--- {fname} ---\n{content}\n"
    return infra_content


def parse_llm_findings(response_text: str, agent_name: str) -> tuple[list[Finding], str]:
    """Parse an LLM JSON response into findings + summary.

    Tolerates a leading/trailing markdown code fence exactly as the core agents
    do. On any parse failure returns ``([], "")`` so callers fall back cleanly.
    """
    text = response_text.strip()
    if text.startswith("```"):
        # Drop the opening fence line and the trailing fence.
        text = text.split("\n", 1)[1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0]

    try:
        result = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], ""

    findings = [
        Finding(
            agent=agent_name,
            category="ai-analysis",
            severity=Severity(f.get("severity", "medium")),
            title=f.get("title", ""),
            description=f.get("description", ""),
            resource=f.get("resource", ""),
            recommendation=f.get("recommendation", ""),
        )
        for f in result.get("findings", [])
        # Guard against a non-dict entry in the findings array.
        if isinstance(f, dict)
    ]
    summary = result.get("summary", "") if isinstance(result, dict) else ""
    return findings, summary


async def run_llm_agent(
    agent_name: str,
    system_prompt: str,
    file_contents: dict[str, str],
    rule_findings: list[Finding] | None = None,
    human_template: str = "Analyze the following infrastructure:\n\n{infra_content}",
) -> AgentReport:
    """Run a single LLM-backed agent and return its ``AgentReport``.

    This is the de-duplicated form of the pattern in ``cost.py`` et al.:
    invoke the LLM with the skill's system prompt, parse findings, dedup LLM
    findings against any deterministic ``rule_findings``, then score by
    severity deductions.

    Args:
        agent_name: ``Finding.agent`` / ``AgentReport.agent_name`` label.
        system_prompt: The skill prompt (may be empty — then only rules count).
        file_contents: Uploaded files (name -> content).
        rule_findings: Deterministic findings to include and dedup against.
        human_template: Prompt template with a ``{infra_content}`` slot.

    Returns:
        An ``AgentReport`` with combined findings, summary, and a 0-100 score.
    """
    rule_findings = rule_findings or []

    llm_findings: list[Finding] = []
    llm_summary = ""

    # An empty system prompt means there is nothing meaningful to ask the LLM;
    # skip the call and score purely on rules (keeps rule_based-style callers cheap).
    if system_prompt:
        llm = get_llm()
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", human_template),
        ])
        chain = prompt | llm
        try:
            response = await chain.ainvoke(
                {"infra_content": _format_infra_content(file_contents)}
            )
            llm_findings, llm_summary = parse_llm_findings(
                response.content.strip(), agent_name
            )
        except Exception as e:  # noqa: BLE001 — mirror core agents' broad fallback
            logger.warning("LLM agent '%s' failed, falling back to rules: %s", agent_name, e)
            llm_findings, llm_summary = [], ""

    all_findings = rule_findings[:]
    for f in llm_findings:
        if not _is_duplicate(f, rule_findings):
            all_findings.append(f)

    score = score_from_findings(all_findings)

    return AgentReport(
        agent_name=agent_name,
        findings=all_findings,
        summary=llm_summary or f"Found {len(all_findings)} issues.",
        score=score,
    )
