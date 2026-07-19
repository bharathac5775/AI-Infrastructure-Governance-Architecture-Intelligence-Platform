import type { Severity } from "@/types/api";
import type { BadgeProps } from "@/components/ui/badge";

// The SPOF/Resilience agent carries an informational score (100) and must be
// excluded from score tiles and the overall average display. Matches the
// Streamlit rule (agent_name != "Resilience Agent").
export const ADVISORY_AGENT = "Resilience Agent";

export function isAdvisoryAgent(agentName: string): boolean {
  return agentName.includes("Resilience");
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityTone(sev: Severity): BadgeProps["tone"] {
  switch (sev) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "info";
    default:
      return "neutral";
  }
}

/** Score → tone for the numeric score display (higher is better). */
export function scoreTone(score: number): BadgeProps["tone"] {
  if (score >= 85) return "success";
  if (score >= 70) return "info";
  if (score >= 50) return "warning";
  return "danger";
}

export function scoreLabel(score: number): string {
  if (score >= 85) return "Strong";
  if (score >= 70) return "Fair";
  if (score >= 50) return "At risk";
  return "Critical";
}

/** Short relative-ish timestamp for report lists. Falls back to the raw ISO. */
export function formatTimestamp(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
