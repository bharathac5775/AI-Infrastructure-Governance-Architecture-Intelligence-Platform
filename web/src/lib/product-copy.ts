import {
  Shield,
  Activity,
  DollarSign,
  Building2,
  ClipboardCheck,
  Network,
  type LucideIcon,
} from "lucide-react";

// Single source of truth for product narrative copy. Every claim here maps to
// a real capability in the backend — no marketing fiction.

export interface AgentCopy {
  name: string;
  icon: LucideIcon;
  blurb: string;
  checks: string;
}

// The six finding-producing agents (Supervisor + Remediator are infrastructure,
// not shown as capabilities). Names match app/agents/* exactly.
export const AGENTS: AgentCopy[] = [
  {
    name: "Security",
    icon: Shield,
    blurb: "Surfaces misconfigurations, exposed secrets, and overly-permissive access before they reach production.",
    checks: "Public exposure · IAM · encryption · secrets",
  },
  {
    name: "Reliability",
    icon: Activity,
    blurb: "Flags missing health checks, absent replicas, and fragile rollout settings that risk downtime.",
    checks: "Probes · replicas · limits · restart policy",
  },
  {
    name: "Cost",
    icon: DollarSign,
    blurb: "Identifies oversized resources, idle capacity, and settings that quietly inflate the monthly bill.",
    checks: "Right-sizing · idle spend · storage tiers",
  },
  {
    name: "Architecture",
    icon: Building2,
    blurb: "Reviews cross-cutting design trade-offs and patterns, weighing decisions no single-resource check can see.",
    checks: "Patterns · trade-offs · prioritized actions",
  },
  {
    name: "Compliance",
    icon: ClipboardCheck,
    blurb: "Scores your infrastructure against CIS benchmarks and maps each finding to the control it violates.",
    checks: "CIS AWS · Azure · GCP · Kubernetes",
  },
  {
    name: "Resilience",
    icon: Network,
    blurb: "Builds a dependency graph to expose single points of failure and the blast radius of each component.",
    checks: "SPOFs · blast radius · dependency graph",
  },
];

export interface StepCopy {
  title: string;
  body: string;
}

export const STEPS: StepCopy[] = [
  {
    title: "Upload or paste",
    body: "Drop Terraform, Kubernetes, or Helm files — or paste config directly. Nothing leaves your machine.",
  },
  {
    title: "Agents analyze locally",
    body: "Six specialized agents review your infrastructure in one pass using a local model — no cloud, no API keys.",
  },
  {
    title: "Review & remediate",
    body: "Get a scored report with prioritized findings, a dependency map, compliance scorecards, and one-click fixes.",
  },
];

// Platform capability chips — each is a shipped feature.
export const CAPABILITIES: string[] = [
  "CIS compliance scoring",
  "Dependency graph & SPOF detection",
  "Deterministic auto-remediation",
  "Drift detection between scans",
  "Auditor-ready PDF export",
  "100% local — no data leaves the box",
];
