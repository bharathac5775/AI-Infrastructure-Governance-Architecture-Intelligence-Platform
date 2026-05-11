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
