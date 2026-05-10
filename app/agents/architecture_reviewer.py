"""Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent findings."""

import json
import logging
from langchain_core.prompts import ChatPromptTemplate
from app.core.llm import get_llm
from app.core.skills import get_agent_prompt
from app.models import (
    AgentReport,
    ArchitectureReview,
    Tradeoff,
    PatternDetected,
    CrossCuttingGap,
    Severity,
)

logger = logging.getLogger(__name__)

import re as _re

# Max characters of raw infra content to send to the reviewer
_MAX_INFRA_CHARS = 8000


def _extract_k8s_resources(content: str) -> list[str]:
    """Extract Kubernetes resource kinds and names from YAML content."""
    resources = []
    docs = content.split("---")
    for doc in docs:
        kind_match = _re.search(r'^kind:\s*(\S+)', doc, _re.MULTILINE)
        name_match = _re.search(r'^\s+name:\s*(\S+)', doc, _re.MULTILINE)
        if kind_match:
            kind = kind_match.group(1)
            name = name_match.group(1) if name_match else "unnamed"
            resources.append(f"{kind}/{name}")
    return resources


def _extract_tf_resources(content: str) -> list[str]:
    """Extract Terraform resource types and names from HCL content."""
    resources = []
    for match in _re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', content):
        resources.append(f"{match.group(1)}.{match.group(2)}")
    return resources


def _build_infrastructure_summary(file_contents: dict[str, str]) -> str:
    """Build a concise summary of infrastructure resources present in the files."""
    if not file_contents:
        return "No infrastructure files provided."

    lines = []
    for filename, content in file_contents.items():
        lines.append(f"--- {filename} ---")

        # Extract resource inventory first (always included, never truncated)
        if filename.endswith((".yaml", ".yml")):
            resources = _extract_k8s_resources(content)
            if resources:
                lines.append(f"Kubernetes resources found: {', '.join(resources)}")
        elif filename.endswith((".tf", ".hcl")):
            resources = _extract_tf_resources(content)
            if resources:
                lines.append(f"Terraform resources found: {', '.join(resources)}")

        # Include raw content (truncated if needed)
        max_per_file = _MAX_INFRA_CHARS // max(len(file_contents), 1)
        if len(content) > max_per_file:
            lines.append(content[:max_per_file] + "\n... (truncated)")
        else:
            lines.append(content)
    return "\n".join(lines)


def _format_findings(report: AgentReport | None) -> str:
    """Format agent findings into a concise string for the reviewer."""
    if not report or not report.findings:
        return "No findings."
    lines = []
    for f in report.findings:
        lines.append(f"[{f.severity.value.upper()}] {f.title}: {f.description}")
    return "\n".join(lines)


async def analyze_architecture(
    security_report: AgentReport | None,
    reliability_report: AgentReport | None,
    cost_report: AgentReport | None,
    file_contents: dict[str, str] | None = None,
    infra_type: str = "mixed",
) -> ArchitectureReview:
    """Run cross-cutting architecture analysis on all agent reports."""
    system_prompt = get_agent_prompt("architecture-reviewer", "all")
    if not system_prompt:
        # Fallback — shouldn't happen if skill file exists
        return ArchitectureReview(summary="Architecture review skill file not found.")

    security_findings = _format_findings(security_report)
    reliability_findings = _format_findings(reliability_report)
    cost_findings = _format_findings(cost_report)
    infrastructure_summary = _build_infrastructure_summary(file_contents or {})

    llm = get_llm(temperature=0.2, num_ctx=8192)
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
    ])

    chain = prompt | llm
    try:
        response = await chain.ainvoke({
            "infrastructure_summary": infrastructure_summary,
            "security_count": len(security_report.findings) if security_report else 0,
            "security_findings": security_findings,
            "reliability_count": len(reliability_report.findings) if reliability_report else 0,
            "reliability_findings": reliability_findings,
            "cost_count": len(cost_report.findings) if cost_report else 0,
            "cost_findings": cost_findings,
            "infra_type": infra_type,
        })
        response_text = response.content.strip()

        # Clean markdown code block if present
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            response_text = response_text.rsplit("```", 1)[0]

        result = json.loads(response_text)

        tradeoffs = [
            Tradeoff(
                title=t.get("title", ""),
                description=t.get("description", ""),
                agents_involved=t.get("agents_involved", []),
                recommendation=t.get("recommendation", ""),
            )
            for t in result.get("tradeoffs", [])
        ]

        patterns = [
            PatternDetected(
                pattern=p.get("pattern", ""),
                assessment=p.get("assessment", "partial"),
                details=p.get("details", ""),
            )
            for p in result.get("patterns_detected", [])
        ]

        gaps = [
            CrossCuttingGap(
                title=g.get("title", ""),
                severity=Severity(g.get("severity", "medium")),
                description=g.get("description", ""),
                recommendation=g.get("recommendation", ""),
            )
            for g in result.get("cross_cutting_gaps", [])
        ]

        return ArchitectureReview(
            tradeoffs=tradeoffs,
            patterns_detected=patterns,
            cross_cutting_gaps=gaps,
            prioritized_actions=result.get("prioritized_actions", []),
            architecture_score=float(result.get("architecture_score", 50)),
            summary=result.get("summary", ""),
        )

    except Exception as e:
        logger.error(f"Architecture reviewer LLM call failed: {e}")
        return ArchitectureReview(
            summary="Architecture review could not be completed due to LLM error.",
            architecture_score=0.0,
        )
