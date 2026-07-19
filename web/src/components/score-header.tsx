import type { AnalysisReport } from "@/types/api";
import { isAdvisoryAgent, scoreTone, scoreLabel } from "@/lib/report-utils";
import { Badge } from "@/components/ui/badge";

const TONE_TEXT: Record<string, string> = {
  success: "text-success",
  info: "text-info",
  warning: "text-warning",
  danger: "text-danger",
  neutral: "text-foreground",
  primary: "text-primary",
};

// Report summary header: the overall governance score as the focal point, then
// per-agent score tiles. The Resilience Agent is informational (score 100) and
// is excluded from tiles — matching the backend's scoring exclusion.
export function ScoreHeader({ report }: { report: AnalysisReport }) {
  const tiles = report.agent_reports.filter((a) => !isAdvisoryAgent(a.agent_name));
  const overallTone = scoreTone(report.overall_score);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[auto,1fr]">
        {/* Overall score */}
        <div className="flex items-center gap-5 rounded-xl border border-border bg-card p-5 surface-raised">
          <div className="flex flex-col items-center">
            <span className={`text-5xl font-semibold tabular tracking-tight ${TONE_TEXT[overallTone!]}`}>
              {report.overall_score.toFixed(0)}
            </span>
            <span className="text-2xs uppercase tracking-wider text-muted-foreground">/ 100</span>
          </div>
          <div className="space-y-1.5">
            <Badge tone={overallTone} dot>
              {scoreLabel(report.overall_score)}
            </Badge>
            <p className="text-2xs uppercase tracking-wider text-muted-foreground">
              Governance score
            </p>
          </div>
        </div>

        {/* Executive summary */}
        <div className="flex flex-col justify-center rounded-xl border border-border bg-card p-5 surface-raised">
          <h3 className="mb-1.5 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
            Executive summary
          </h3>
          <p className="text-sm leading-relaxed text-foreground/90">
            {report.executive_summary || "No summary available."}
          </p>
        </div>
      </div>

      {/* Per-agent score tiles */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {tiles.map((a) => {
          const tone = scoreTone(a.score);
          return (
            <div
              key={a.agent_name}
              className="rounded-lg border border-border bg-card p-3.5 surface-raised"
            >
              <p className="truncate text-xs font-medium text-muted-foreground">
                {a.agent_name.replace(" Agent", "")}
              </p>
              <p className={`mt-1 text-2xl font-semibold tabular ${TONE_TEXT[tone!]}`}>
                {a.score.toFixed(0)}
              </p>
              <p className="text-2xs text-muted-foreground">
                {a.findings.length} finding{a.findings.length === 1 ? "" : "s"}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
