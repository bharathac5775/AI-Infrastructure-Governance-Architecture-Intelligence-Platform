from pydantic import BaseModel
from typing import Optional
from enum import Enum
import uuid
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    agent: str
    category: str
    severity: Severity
    title: str
    description: str
    resource: str
    recommendation: str
    # Phase 3.3 — compliance enrichment. Empty default so old findings (and
    # findings constructed before the enrichment step runs) deserialize cleanly.
    compliance_controls: list[str] = []


class AgentReport(BaseModel):
    agent_name: str
    findings: list[Finding] = []
    summary: str
    score: float  # 0-100


class Tradeoff(BaseModel):
    title: str
    description: str
    agents_involved: list[str] = []
    recommendation: str


class PatternDetected(BaseModel):
    pattern: str
    assessment: str  # "good", "anti-pattern", "partial"
    details: str


class CrossCuttingGap(BaseModel):
    title: str
    severity: Severity
    description: str
    recommendation: str


class ArchitectureReview(BaseModel):
    tradeoffs: list[Tradeoff] = []
    patterns_detected: list[PatternDetected] = []
    cross_cutting_gaps: list[CrossCuttingGap] = []
    prioritized_actions: list[str] = []
    architecture_score: float
    summary: str


# Phase 3.3 — Compliance scorecard models
class ComplianceFrameworkScore(BaseModel):
    framework_id: str                          # e.g. "cis_kubernetes"
    framework_name: str                        # e.g. "CIS Kubernetes Benchmark"
    version: str
    score_pct: float                           # 0-100
    controls_passed: list[str] = []            # control IDs with no failed findings
    controls_failed: list[str] = []            # control IDs with at least one finding


class ComplianceScorecard(BaseModel):
    frameworks: list[ComplianceFrameworkScore] = []


# Phase 4.1 / 4.5 — dependency graph + SPOF models. Serializable snapshot of the
# NetworkX graph so it can be persisted on the report and served by the
# blast-radius / diagram endpoints without re-parsing the original files.
class GraphNode(BaseModel):
    id: str                                   # e.g. "Deployment/prod/api" or "aws_db_instance.db"
    kind: str                                 # K8s kind or TF resource type
    platform: str                             # "kubernetes" | "terraform"
    present: bool = True                      # False if only referenced, not uploaded


class GraphEdge(BaseModel):
    source: str                               # dependent
    target: str                               # dependency (source depends on target)
    relation: str                             # "reference" | "selects" | "secretKeyRef" | ...


class Spof(BaseModel):
    node: str
    kind: str
    platform: str
    dependent_count: int
    dependents: list[str] = []
    reasons: list[str] = []                   # "high-fan-in" | "articulation-point"
    is_articulation: bool = False


class DependencyGraph(BaseModel):
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    spofs: list[Spof] = []


class AnalysisReport(BaseModel):
    report_id: str = ""
    timestamp: str = ""
    files_analyzed: list[str] = []
    agent_reports: list[AgentReport] = []
    architecture_review: Optional[ArchitectureReview] = None
    overall_score: float
    executive_summary: str
    risk_summary: str
    recommendations: list[str] = []
    # Phase 3.2 — drift detection. Defaults are safe so old persisted reports
    # without these fields still deserialize.
    file_fingerprints: dict[str, str] = {}    # filename -> sha256 hex
    bundle_fingerprint: str = ""              # sha256 over sorted (filename, hash) pairs
    # Phase 3.3 — compliance scorecard. None default so old reports deserialize.
    compliance: Optional[ComplianceScorecard] = None
    # Phase 4.1/4.5 — dependency graph + SPOFs. None default so old persisted
    # reports (and non-infra uploads with no resources) deserialize cleanly.
    dependency_graph: Optional[DependencyGraph] = None
    # Phase 3.4 — file contents echoed back from /analyze ONLY (never persisted).
    # Lets the frontend cache the post-render YAML for .tgz uploads (where the
    # text is created server-side) and pasted-content uploads. Stripped before
    # ChromaDB persistence by save_report — see app/core/store.py.
    file_contents: dict[str, str] = {}

    def __init__(self, **data):
        super().__init__(**data)
        if not self.report_id:
            self.report_id = str(uuid.uuid4())[:8]
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class AnalysisRequest(BaseModel):
    file_contents: dict[str, str]  # filename -> content
    analysis_types: list[str] = ["security", "reliability", "cost"]


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.2.0"
    agents: list[str] = ["security", "reliability", "cost", "architecture-reviewer"]


# Phase 3.4 — Auto-Remediation
class Patch(BaseModel):
    """A generated fix for a single Finding.

    The remediator returns the *patched file content* plus a unified diff for
    display. The caller is responsible for applying the patch to their working
    tree — we never write to disk on the server.

    `validation_status` reports whether the patched output parses cleanly:
        - "valid"          : re-parse succeeded
        - "unparseable"    : re-parse failed (LLM-generated only — would be
                              rejected before reaching the caller, but the
                              field exists for transparency)
        - "not_applicable" : a deterministic fixer hand-built the patch and
                              we trust the construction (still re-parses to
                              double-check; this status means the validator
                              chose not to enforce, e.g. partial-file mode)
    """
    finding_index: int
    finding_title: str
    filename: str
    original_content: str
    patched_content: str
    unified_diff: str
    strategy: str               # "deterministic" | "llm" | "manual_required"
    validation_status: str      # "valid" | "unparseable" | "not_applicable"
    explanation: str            # Short human-readable summary of what the patch does
    warnings: list[str] = []    # Non-fatal notes (e.g. "fixer assumed default namespace")
