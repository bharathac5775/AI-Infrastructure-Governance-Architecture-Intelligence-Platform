"""Per-agent score deductions table.

This duplicates the table from app/agents/{security,reliability,cost}.py
so test_samples_rules_only can compute the deterministic per-agent score
without going through the LLM-augmented analyze_*() entry points.

If the deductions table changes in production, update here AND in all three
agent files. The unit test test_deduction_table_in_sync_with_security_agent
guards against drift.
"""
from app.models import Severity

SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def compute_agent_score(findings: list) -> float:
    """Apply the standard deduction table to a list of Finding objects."""
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTIONS[f.severity]
    return float(max(0, score))
