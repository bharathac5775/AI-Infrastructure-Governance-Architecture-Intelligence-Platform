"""Shared utility functions for agent deduplication."""

from app.models import Finding

# Stop words excluded from keyword matching
STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "will", "would", "could", "should", "may",
    "might", "can", "shall", "to", "of", "in", "for", "on", "with", "at",
    "by", "from", "as", "into", "through", "during", "before", "after",
    "and", "but", "or", "nor", "not", "no", "so", "if", "than", "too",
    "it", "its", "this", "that", "these", "those", "set", "add", "use",
})

# Domain synonyms for better dedup matching
SYNONYMS = {
    "missing": "no", "no": "missing", "lacks": "missing", "absent": "missing",
    "without": "missing", "undefined": "missing",
    "limits": "limit", "limit": "limits",
    "requests": "request", "request": "requests",
    "probes": "probe", "probe": "probes",
    "replicas": "replica", "replica": "replicas",
    "securitycontext": "security", "security": "securitycontext",
    "root": "nonroot", "nonroot": "root", "runasnonroot": "root",
    "image": "tag", "tag": "image", "latest": "untagged", "untagged": "latest",
    "secret": "password", "password": "secret", "credential": "secret",
    "credentials": "secret", "hardcoded": "plaintext", "plaintext": "hardcoded",
    "loadbalancer": "public", "public": "loadbalancer",
    "hpa": "autoscaling", "autoscaling": "hpa", "autoscaler": "hpa",
    "pdb": "disruption", "disruption": "pdb",
    "affinity": "antiaffinity", "antiaffinity": "affinity",
    "liveness": "health", "readiness": "health", "health": "liveness",
    "standalone": "single", "single": "standalone",
    "asg": "scaling", "scaling": "asg",
    "deletion": "delete", "delete": "deletion", "protection": "deletion",
    "multiaz": "multi", "multi": "multiaz",
    "overprovisioned": "oversized", "oversized": "overprovisioned", "rightsizing": "oversized",
}


def extract_keywords(text: str) -> set[str]:
    """Extract significant keywords from text, with synonym expansion."""
    words = set()
    for w in text.lower().replace("-", " ").replace("_", " ").replace("/", " ").split():
        w = w.strip(".,;:!?()[]{}\"'`")
        if len(w) > 2 and w not in STOP_WORDS:
            words.add(w)
            if w in SYNONYMS:
                words.add(SYNONYMS[w])
    return words


def is_duplicate(llm_finding: Finding, rule_findings: list[Finding]) -> bool:
    """Check if an LLM finding duplicates any rule finding using keyword overlap."""
    llm_keywords = extract_keywords(llm_finding.title + " " + llm_finding.description)
    if not llm_keywords:
        return False
    for rf in rule_findings:
        rule_keywords = extract_keywords(rf.title + " " + rf.description + " " + rf.category)
        overlap = llm_keywords & rule_keywords
        if len(overlap) >= max(2, len(llm_keywords) * 0.25):
            return True
    return False
