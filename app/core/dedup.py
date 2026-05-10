"""Shared utility functions for agent deduplication."""

import re
from app.models import Finding

# Stop words excluded from keyword matching — includes generic qualifiers like
# "missing/no/lacks" that appear in almost every finding and add no signal
STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "will", "would", "could", "should", "may",
    "might", "can", "shall", "to", "of", "in", "for", "on", "with", "at",
    "by", "from", "as", "into", "through", "during", "before", "after",
    "and", "but", "or", "nor", "not", "no", "so", "if", "than", "too",
    "it", "its", "this", "that", "these", "those", "set", "add", "use",
    # Generic qualifiers — present in almost every finding, not useful for overlap
    "missing", "lacks", "absent", "without", "undefined",
})

# Domain synonyms for better dedup matching.
# Rules:
#  - Plurals normalize to singular (one direction only, e.g. "probes"→"probe")
#  - Distinct probe types (liveness vs readiness) are NOT collapsed — they are
#    different findings that should not deduplicate each other
SYNONYMS = {
    "limits": "limit",
    "requests": "request",
    "probes": "probe",                           # plural→singular only
    "replicas": "replica",
    "securitycontext": "security", "security": "securitycontext",
    "root": "nonroot", "nonroot": "root", "runasnonroot": "root",
    "image": "tag", "tag": "image", "latest": "untagged", "untagged": "latest",
    "secret": "password", "password": "secret", "credential": "secret",
    "credentials": "secret", "hardcoded": "plaintext", "plaintext": "hardcoded",
    "loadbalancer": "public", "public": "loadbalancer",
    "hpa": "autoscaling", "autoscaling": "hpa", "autoscaler": "hpa",
    "pdb": "disruption", "disruption": "pdb",
    "affinity": "antiaffinity", "antiaffinity": "affinity",
    "health": "probe",                           # "health check" → matches probe rules
    "standalone": "single", "single": "standalone",
    "asg": "scaling", "scaling": "asg",
    "deletion": "delete", "delete": "deletion", "protection": "deletion",
    "multiaz": "multi", "multi": "multiaz",
    "overprovisioned": "oversized", "oversized": "overprovisioned", "rightsizing": "oversized",
}


def _split_camelcase(text: str) -> str:
    """Insert spaces at camelCase and PascalCase boundaries.

    'HorizontalPodAutoscaler' -> 'Horizontal Pod Autoscaler'
    'PodDisruptionBudget'     -> 'Pod Disruption Budget'
    'runAsNonRoot'            -> 'run As Non Root'
    """
    text = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    return text


def extract_keywords(text: str) -> set[str]:
    """Extract significant keywords from text, with synonym expansion."""
    text = _split_camelcase(text)
    words = set()
    for w in text.lower().replace("-", " ").replace("_", " ").replace("/", " ").split():
        w = w.strip(".,;:!?()[]{}\"'`")
        if len(w) > 2 and w not in STOP_WORDS:
            words.add(w)
            syn = SYNONYMS.get(w)
            if syn and syn not in STOP_WORDS:   # don't inject stop words via synonym
                words.add(syn)
    return words


def is_duplicate(llm_finding: Finding, rule_findings: list[Finding]) -> bool:
    """Check if an LLM finding duplicates any rule finding using keyword overlap."""
    llm_keywords = extract_keywords(llm_finding.title + " " + llm_finding.description)
    if not llm_keywords:
        return False
    for rf in rule_findings:
        rule_keywords = extract_keywords(rf.title + " " + rf.description + " " + rf.category)
        overlap = llm_keywords & rule_keywords
        if len(overlap) >= max(3, len(llm_keywords) * 0.20):
            return True
    return False
