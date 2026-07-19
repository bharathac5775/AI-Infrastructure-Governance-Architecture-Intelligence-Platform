import { useQuery } from "@tanstack/react-query";
import { GitCompareArrows, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { api } from "@/lib/api";
import { LoadingState, EmptyState } from "@/components/ui/states";
import { Badge } from "@/components/ui/badge";
import { formatTimestamp } from "@/lib/report-utils";
import { cn } from "@/lib/utils";

// Drift vs. the most recent prior scan of the same bundle. Null-safe: shows a
// neutral empty state when no baseline exists (first scan of this bundle).
export function DriftPanel({ reportId }: { reportId: string }) {
  const drift = useQuery({
    queryKey: ["drift", reportId],
    queryFn: () => api.drift(reportId),
  });

  if (drift.isLoading) return <LoadingState label="Checking for drift" />;

  const d = drift.data?.drift;
  if (!d) {
    return (
      <EmptyState
        icon={<GitCompareArrows />}
        title="No prior scan to compare"
        description="Drift appears once you analyze the same set of files a second time. Re-run this bundle later to see what changed."
      />
    );
  }

  const introduced = d.findings_introduced.length;
  const resolved = d.findings_resolved.length;

  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Compared against baseline{" "}
        <span className="font-mono text-foreground">{d.baseline.report_id}</span> from{" "}
        {formatTimestamp(d.baseline.timestamp)}.
      </p>

      {/* Score deltas */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {Object.entries(d.score_deltas).map(([key, delta]) => (
          <div key={key} className="rounded-lg border border-border bg-card p-3.5 surface-raised">
            <p className="truncate text-xs font-medium capitalize text-muted-foreground">{key}</p>
            <DeltaValue delta={delta} />
          </div>
        ))}
      </div>

      {/* Introduced / resolved buckets */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <DriftBucket
          title="Introduced"
          tone="danger"
          count={introduced}
          findings={d.findings_introduced}
          emptyLabel="No new findings"
        />
        <DriftBucket
          title="Resolved"
          tone="success"
          count={resolved}
          findings={d.findings_resolved}
          emptyLabel="No findings resolved"
        />
      </div>
    </div>
  );
}

function DeltaValue({ delta }: { delta: number | null }) {
  if (delta === null) return <p className="mt-1 text-2xl font-semibold tabular text-muted-foreground">—</p>;
  const Icon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus;
  const tone = delta > 0 ? "text-success" : delta < 0 ? "text-danger" : "text-muted-foreground";
  return (
    <p className={cn("mt-1 flex items-center gap-1 text-2xl font-semibold tabular", tone)}>
      <Icon className="size-4" />
      {delta > 0 ? "+" : ""}
      {delta.toFixed(1)}
    </p>
  );
}

function DriftBucket({
  title,
  tone,
  count,
  findings,
  emptyLabel,
}: {
  title: string;
  tone: "danger" | "success";
  count: number;
  findings: { title: string; severity: string; resource: string }[];
  emptyLabel: string;
}) {
  return (
    <div className="surface-raised rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center gap-2">
        <Badge tone={tone} dot>
          {title}
        </Badge>
        <span className="text-xs tabular text-muted-foreground">{count}</span>
      </div>
      {count === 0 ? (
        <p className="py-4 text-center text-sm text-muted-foreground">{emptyLabel}</p>
      ) : (
        <ul className="space-y-2">
          {findings.map((f, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-current opacity-40" />
              <div className="min-w-0">
                <p className="truncate font-medium">{f.title}</p>
                {f.resource && (
                  <p className="truncate font-mono text-xs text-muted-foreground">{f.resource}</p>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
