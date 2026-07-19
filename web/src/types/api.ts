// TypeScript mirrors of app/models.py. Kept in lockstep with the backend
// Pydantic models — these are the wire types returned by the FastAPI JSON API.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  agent: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  resource: string;
  recommendation: string;
  compliance_controls: string[];
}

export interface AgentReport {
  agent_name: string;
  findings: Finding[];
  summary: string;
  score: number;
}

export interface Tradeoff {
  title: string;
  description: string;
  agents_involved: string[];
  recommendation: string;
}

export interface PatternDetected {
  pattern: string;
  assessment: string;
  details: string;
}

export interface CrossCuttingGap {
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
}

export interface ArchitectureReview {
  tradeoffs: Tradeoff[];
  patterns_detected: PatternDetected[];
  cross_cutting_gaps: CrossCuttingGap[];
  prioritized_actions: string[];
  architecture_score: number;
  summary: string;
}

export interface ComplianceFrameworkScore {
  framework_id: string;
  framework_name: string;
  version: string;
  score_pct: number;
  controls_passed: string[];
  controls_failed: string[];
}

export interface ComplianceScorecard {
  frameworks: ComplianceFrameworkScore[];
}

export interface GraphNode {
  id: string;
  kind: string;
  platform: string;
  present: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface Spof {
  node: string;
  kind: string;
  platform: string;
  dependent_count: number;
  dependents: string[];
  reasons: string[];
  is_articulation: boolean;
}

export interface DependencyGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  spofs: Spof[];
}

export interface AnalysisReport {
  report_id: string;
  timestamp: string;
  files_analyzed: string[];
  agent_reports: AgentReport[];
  architecture_review: ArchitectureReview | null;
  overall_score: number;
  executive_summary: string;
  risk_summary: string;
  recommendations: string[];
  file_fingerprints: Record<string, string>;
  bundle_fingerprint: string;
  compliance: ComplianceScorecard | null;
  dependency_graph: DependencyGraph | null;
  file_contents: Record<string, string>;
}

export interface Patch {
  finding_index: number;
  finding_title: string;
  filename: string;
  original_content: string;
  patched_content: string;
  unified_diff: string;
  strategy: string; // "deterministic" | "llm" | "manual_required"
  validation_status: string;
  explanation: string;
  warnings: string[];
}

export interface ReportListItem {
  report_id: string;
  timestamp: string;
  overall_score: number;
  files_analyzed: string; // NOTE: comma-joined string in the list (not array)
  file_count: number;
  security_agent_score?: number;
  reliability_agent_score?: number;
  cost_agent_score?: number;
  architecture_score?: number;
}

export interface CompareResult {
  report_a: { id: string; timestamp: string };
  report_b: { id: string; timestamp: string };
  overall_delta: number;
  security_delta: number;
  reliability_delta: number;
  cost_delta: number;
  findings_delta: number;
  scores: {
    before: Record<string, number>;
    after: Record<string, number>;
  };
}

export interface BlastRadius {
  resource: string;
  found: boolean;
  direct_dependents: string[];
  transitive_dependents: string[];
  impact_count: number;
  criticality: string; // "critical" | "high" | ... | "unknown"
  is_spof: boolean;
}

export interface DriftDetail {
  baseline: { report_id: string; timestamp: string };
  current: { report_id: string; timestamp: string };
  score_deltas: Record<string, number | null>;
  findings_introduced: Finding[];
  findings_resolved: Finding[];
  findings_persisting: Finding[];
  severity_summary: {
    introduced: Record<string, number>;
    resolved: Record<string, number>;
    persisting: Record<string, number>;
  };
}

export interface DriftResponse {
  baseline: { report_id: string; timestamp: string } | null;
  drift: DriftDetail | null;
}

export interface HealthResponse {
  status: string;
  version: string;
  agents: string[];
}
