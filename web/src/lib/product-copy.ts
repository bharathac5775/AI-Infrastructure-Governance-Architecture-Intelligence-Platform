import {
  Shield,
  Activity,
  DollarSign,
  Building2,
  ClipboardCheck,
  Network,
  Bot,
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

// Per-agent identity: icon + a distinct hue. One place so the home cards, the
// findings table agent column, and the finding detail all render agents the
// same way — a colored glyph is far easier to scan than repeated plain text.
export interface AgentVisual {
  icon: LucideIcon;
  /** Icon color. */
  fg: string;
  /** Tinted tile background + hairline, tuned for both themes. */
  tile: string;
}

const AGENT_VISUALS: Record<string, AgentVisual> = {
  Security: {
    icon: Shield,
    fg: "text-rose-500 dark:text-rose-400",
    tile: "bg-rose-500/10 border-rose-500/20",
  },
  Reliability: {
    icon: Activity,
    fg: "text-emerald-500 dark:text-emerald-400",
    tile: "bg-emerald-500/10 border-emerald-500/20",
  },
  Cost: {
    icon: DollarSign,
    fg: "text-amber-500 dark:text-amber-400",
    tile: "bg-amber-500/10 border-amber-500/20",
  },
  Architecture: {
    icon: Building2,
    fg: "text-violet-500 dark:text-violet-400",
    tile: "bg-violet-500/10 border-violet-500/20",
  },
  Compliance: {
    icon: ClipboardCheck,
    fg: "text-sky-500 dark:text-sky-400",
    tile: "bg-sky-500/10 border-sky-500/20",
  },
  Resilience: {
    icon: Network,
    fg: "text-teal-500 dark:text-teal-400",
    tile: "bg-teal-500/10 border-teal-500/20",
  },
};

const FALLBACK_VISUAL: AgentVisual = {
  icon: Bot,
  fg: "text-indigo-500 dark:text-indigo-400",
  tile: "bg-indigo-500/10 border-indigo-500/20",
};

// Accepts either the short name ("Security") or the full finding agent label
// ("Security Agent"), so callers don't have to normalize first.
export function agentVisual(agent: string): AgentVisual {
  for (const key of Object.keys(AGENT_VISUALS)) {
    if (agent.includes(key)) return AGENT_VISUALS[key];
  }
  return FALLBACK_VISUAL;
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
    body: "Add Terraform, Kubernetes, or Helm files — or paste config directly. Every supported format normalizes into a single review pass.",
  },
  {
    title: "Six agents analyze",
    body: "Specialized agents examine your infrastructure in one pass, each scoring its dimension and mapping issues to the resources that cause them.",
  },
  {
    title: "Review & remediate",
    body: "Get a scored report with prioritized findings, a dependency map, compliance scorecards, and code-level fixes you can apply.",
  },
];

// Platform capability chips — each is a shipped feature.
export const CAPABILITIES: string[] = [
  "Weighted governance scoring",
  "CIS compliance scorecards",
  "Dependency graph & SPOF detection",
  "Blast-radius analysis",
  "Deterministic auto-remediation",
  "Drift detection between scans",
  "Auditor-ready PDF export",
];
