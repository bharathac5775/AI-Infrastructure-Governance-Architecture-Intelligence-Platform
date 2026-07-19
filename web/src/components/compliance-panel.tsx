import type { AnalysisReport } from "@/types/api";
import { EmptyState } from "@/components/ui/states";
import { Badge } from "@/components/ui/badge";
import { ClipboardCheck } from "lucide-react";
import { scoreTone } from "@/lib/report-utils";

const TONE_TEXT: Record<string, string> = {
  success: "text-success",
  info: "text-info",
  warning: "text-warning",
  danger: "text-danger",
  neutral: "text-foreground",
  primary: "text-primary",
};

// Compliance scorecards from report.compliance — one card per framework, with a
// pass-rate bar and passed/failed control counts.
export function CompliancePanel({ report }: { report: AnalysisReport }) {
  const frameworks = report.compliance?.frameworks ?? [];

  if (frameworks.length === 0) {
    return (
      <EmptyState
        icon={<ClipboardCheck />}
        title="No compliance frameworks matched"
        description="No CIS benchmark applied to this configuration — the detected platform had no mapped framework, or this report predates compliance scoring."
      />
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      {frameworks.map((fw) => {
        const tone = scoreTone(fw.score_pct);
        const total = fw.controls_passed.length + fw.controls_failed.length;
        return (
          <div
            key={fw.framework_id}
            className="surface-raised rounded-lg border border-border bg-card p-5"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="truncate text-sm font-semibold">{fw.framework_name}</h3>
                <p className="mt-0.5 text-xs text-muted-foreground">v{fw.version}</p>
              </div>
              <span className={`shrink-0 text-2xl font-semibold tabular ${TONE_TEXT[tone!]}`}>
                {fw.score_pct.toFixed(0)}%
              </span>
            </div>

            {/* Pass-rate bar */}
            <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className={`h-full rounded-full ${
                  tone === "success"
                    ? "bg-success"
                    : tone === "info"
                      ? "bg-info"
                      : tone === "warning"
                        ? "bg-warning"
                        : "bg-danger"
                }`}
                style={{ width: `${Math.max(2, fw.score_pct)}%` }}
              />
            </div>

            <div className="mt-4 flex items-center gap-2 text-xs">
              <Badge tone="success">{fw.controls_passed.length} passed</Badge>
              <Badge tone={fw.controls_failed.length > 0 ? "danger" : "neutral"}>
                {fw.controls_failed.length} failed
              </Badge>
              <span className="text-muted-foreground">of {total} controls</span>
            </div>

            {fw.controls_failed.length > 0 && (
              <div className="mt-4">
                <p className="mb-1.5 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                  Failing controls
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {fw.controls_failed.map((c) => (
                    <span
                      key={c}
                      className="rounded border border-danger/25 bg-danger/10 px-1.5 py-0.5 font-mono text-2xs text-danger"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
