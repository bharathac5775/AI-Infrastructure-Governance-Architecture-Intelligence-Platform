import { Landmark, Scale, Puzzle, Crosshair, ListChecks } from "lucide-react";
import type { ReactNode } from "react";
import type { AnalysisReport, PatternDetected } from "@/types/api";
import { EmptyState } from "@/components/ui/states";
import { Badge } from "@/components/ui/badge";
import type { BadgeProps } from "@/components/ui/badge";
import { scoreTone, scoreLabel, severityTone } from "@/lib/report-utils";
import { cn } from "@/lib/utils";

// The LLM architecture review: score + summary, cross-agent tradeoffs, detected
// patterns, cross-cutting gaps, and prioritized actions. This is the narrative
// counterpart to the dependency graph (which lives in the Dependencies tab).
// Reads report.architecture_review — produced by app/agents/architecture_reviewer.py.

// pattern assessment ("good" | "partial" | "anti-pattern" | free text) → tone.
function patternTone(assessment: string): BadgeProps["tone"] {
  const a = assessment.toLowerCase();
  if (a.includes("anti")) return "danger";
  if (a.includes("partial")) return "warning";
  if (a.includes("good") || a.includes("strong")) return "success";
  return "neutral";
}

// Section heading with a colored icon tile — distinct hue per section so the
// review scans at a glance, matching the vivid agent-card treatment on Home.
function SectionHeading({
  icon,
  fg,
  tile,
  title,
  count,
}: {
  icon: ReactNode;
  fg: string;
  tile: string;
  title: string;
  count?: number;
}) {
  return (
    <div className="mb-3 flex items-center gap-2.5">
      <span className={cn("flex size-7 items-center justify-center rounded-lg border", tile, fg)}>
        {icon}
      </span>
      <h3 className="text-base font-semibold tracking-tight">{title}</h3>
      {count !== undefined && (
        <span className="rounded bg-secondary px-1.5 py-0.5 text-2xs tabular text-muted-foreground">
          {count}
        </span>
      )}
    </div>
  );
}

export function ArchitectureReviewPanel({ report }: { report: AnalysisReport }) {
  const review = report.architecture_review;

  const isEmpty =
    !review ||
    (!review.summary &&
      review.tradeoffs.length === 0 &&
      review.patterns_detected.length === 0 &&
      review.cross_cutting_gaps.length === 0 &&
      review.prioritized_actions.length === 0);

  if (isEmpty) {
    return (
      <EmptyState
        icon={<Scale />}
        title="No architecture review"
        description="This report has no architecture review — it may have been analyzed before the architecture agent was added, or the content produced no cross-cutting findings."
      />
    );
  }

  const r = review!;

  return (
    <div className="space-y-6">
      {/* Score + summary banner */}
      <div className="surface-raised overflow-hidden rounded-xl border border-border bg-card">
        <div className="flex items-start gap-4 p-5">
          <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/10 text-violet-500 dark:text-violet-400">
            <Landmark className="size-6" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center gap-2">
              <h2 className="text-base font-semibold tracking-tight">Architecture Review</h2>
              <Badge tone={scoreTone(r.architecture_score)} dot>
                {scoreLabel(r.architecture_score)}
              </Badge>
            </div>
            <div className="flex items-baseline gap-1">
              <span className={cn("text-3xl font-semibold tabular", scoreTextClass(r.architecture_score))}>
                {Math.round(r.architecture_score)}
              </span>
              <span className="text-base font-normal text-muted-foreground">/ 100</span>
              <span className="ml-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                Architecture score
              </span>
            </div>
          </div>
        </div>
        {r.summary && (
          <p className="border-t border-border bg-surface/40 px-5 py-4 text-[0.9375rem] leading-relaxed text-muted-foreground">
            {r.summary}
          </p>
        )}
      </div>

      {/* Tradeoffs */}
      {r.tradeoffs.length > 0 && (
        <section>
          <SectionHeading
            icon={<Scale className="size-4" />}
            fg="text-amber-500 dark:text-amber-400"
            tile="bg-amber-500/10 border-amber-500/20"
            title="Tradeoff conflicts"
            count={r.tradeoffs.length}
          />
          <div className="space-y-3">
            {r.tradeoffs.map((t, i) => (
              <div key={i} className="surface-raised rounded-lg border border-border bg-card p-4">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <h4 className="text-sm font-semibold">{t.title}</h4>
                  {t.agents_involved.map((a) => (
                    <Badge key={a} tone="neutral">
                      {a}
                    </Badge>
                  ))}
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground">{t.description}</p>
                {t.recommendation && (
                  <p className="mt-2 border-t border-border pt-2 text-sm leading-relaxed">
                    <span className="font-medium text-foreground">Recommendation: </span>
                    <span className="text-muted-foreground">{t.recommendation}</span>
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Patterns detected */}
      {r.patterns_detected.length > 0 && (
        <section>
          <SectionHeading
            icon={<Puzzle className="size-4" />}
            fg="text-emerald-500 dark:text-emerald-400"
            tile="bg-emerald-500/10 border-emerald-500/20"
            title="Architectural patterns"
            count={r.patterns_detected.length}
          />
          <div className="space-y-3">
            {r.patterns_detected.map((p: PatternDetected, i) => (
              <div key={i} className="surface-raised rounded-lg border border-border bg-card p-4">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <h4 className="text-sm font-semibold">{p.pattern}</h4>
                  <Badge tone={patternTone(p.assessment)}>{p.assessment}</Badge>
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground">{p.details}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Cross-cutting gaps */}
      {r.cross_cutting_gaps.length > 0 && (
        <section>
          <SectionHeading
            icon={<Crosshair className="size-4" />}
            fg="text-rose-500 dark:text-rose-400"
            tile="bg-rose-500/10 border-rose-500/20"
            title="Cross-cutting gaps"
            count={r.cross_cutting_gaps.length}
          />
          <div className="space-y-3">
            {r.cross_cutting_gaps.map((g, i) => (
              <div key={i} className="surface-raised rounded-lg border border-border bg-card p-4">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <Badge tone={severityTone(g.severity)} dot>
                    {g.severity}
                  </Badge>
                  <h4 className="text-sm font-semibold">{g.title}</h4>
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground">{g.description}</p>
                {g.recommendation && (
                  <p className="mt-2 border-t border-border pt-2 text-sm leading-relaxed">
                    <span className="font-medium text-foreground">Recommendation: </span>
                    <span className="text-muted-foreground">{g.recommendation}</span>
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Prioritized actions */}
      {r.prioritized_actions.length > 0 && (
        <section>
          <SectionHeading
            icon={<ListChecks className="size-4" />}
            fg="text-indigo-500 dark:text-indigo-400"
            tile="bg-indigo-500/10 border-indigo-500/20"
            title="Prioritized actions"
            count={r.prioritized_actions.length}
          />
          <ol className="surface-raised space-y-0 overflow-hidden rounded-lg border border-border bg-card">
            {r.prioritized_actions.map((action, i) => (
              <li
                key={i}
                className="flex items-start gap-3 border-b border-border px-4 py-3 text-sm last:border-0"
              >
                <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-2xs font-semibold tabular text-primary">
                  {i + 1}
                </span>
                <span className="leading-relaxed">{action}</span>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}

// Numeric-score color, mirroring scoreTone but for text.
function scoreTextClass(score: number): string {
  if (score >= 85) return "text-success";
  if (score >= 70) return "text-info";
  if (score >= 50) return "text-warning";
  return "text-danger";
}
