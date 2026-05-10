from app.models import AnalysisReport, AgentReport, ArchitectureReview, Severity
from typing import Optional


def calculate_overall_score(
    agent_reports: list[AgentReport],
    architecture_review: Optional[ArchitectureReview] = None,
) -> float:
    """Calculate weighted overall score from agent reports + architecture review."""
    if not agent_reports:
        return 0.0
    weights = {
        "Security Agent": 0.34,
        "Reliability Agent": 0.30,
        "Cost Agent": 0.21,
    }
    total_weight = 0.0
    weighted_score = 0.0
    for report in agent_reports:
        w = weights.get(report.agent_name, 0.28)
        weighted_score += report.score * w
        total_weight += w

    if architecture_review is not None:
        arch_weight = 0.15
        weighted_score += architecture_review.architecture_score * arch_weight
        total_weight += arch_weight

    return round(weighted_score / total_weight, 1) if total_weight > 0 else 0.0


def severity_counts(report: AnalysisReport) -> dict[str, int]:
    """Count findings by severity across all agents."""
    counts = {s.value: 0 for s in Severity}
    for agent_report in report.agent_reports:
        for finding in agent_report.findings:
            counts[finding.severity.value] += 1
    return counts


def format_report_text(report: AnalysisReport) -> str:
    """Format report as readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("INFRASTRUCTURE GOVERNANCE REPORT")
    lines.append(f"Report ID: {report.report_id}")
    lines.append(f"Timestamp: {report.timestamp}")
    lines.append(f"Overall Score: {report.overall_score}/100")
    lines.append("=" * 60)

    counts = severity_counts(report)
    lines.append(f"\nFindings: Critical={counts['critical']} High={counts['high']} "
                 f"Medium={counts['medium']} Low={counts['low']} Info={counts['info']}")

    lines.append(f"\n--- Executive Summary ---\n{report.executive_summary}")
    lines.append(f"\n--- Risk Summary ---\n{report.risk_summary}")

    for agent_report in report.agent_reports:
        lines.append(f"\n{'='*40}")
        lines.append(f"Agent: {agent_report.agent_name} (Score: {agent_report.score}/100)")
        lines.append(f"Summary: {agent_report.summary}")
        for f in agent_report.findings:
            lines.append(f"\n  [{f.severity.value.upper()}] {f.title}")
            lines.append(f"  Resource: {f.resource}")
            lines.append(f"  {f.description}")
            lines.append(f"  → {f.recommendation}")

    if report.recommendations:
        lines.append(f"\n{'='*40}")
        lines.append("TOP RECOMMENDATIONS:")
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"  {i}. {rec}")

    return "\n".join(lines)
