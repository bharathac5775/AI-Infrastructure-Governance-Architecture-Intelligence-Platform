import { useState, lazy, Suspense } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network, AlertTriangle, Crosshair } from "lucide-react";
import type { AnalysisReport } from "@/types/api";
import { api } from "@/lib/api";
import { EmptyState, Spinner } from "@/components/ui/states";
import { Badge } from "@/components/ui/badge";

// Mermaid (and its large diagram engine) is loaded only when this panel opens,
// keeping it out of the initial bundle.
const Mermaid = lazy(() =>
  import("@/components/mermaid").then((m) => ({ default: m.Mermaid }))
);

// Architecture & dependencies: the Mermaid dependency diagram, a SPOF list, and
// an interactive blast-radius picker. All served from the graph persisted on the
// report, so historical reports work without re-parsing.
export function ArchitecturePanel({ report }: { report: AnalysisReport }) {
  const graph = report.dependency_graph;
  const [highlight, setHighlight] = useState<string | null>(null);

  const diagram = useQuery({
    queryKey: ["diagram", report.report_id, highlight],
    queryFn: () => api.diagram(report.report_id, highlight ?? undefined),
    enabled: !!graph,
  });

  const blast = useQuery({
    queryKey: ["blast", report.report_id, highlight],
    queryFn: () => api.blastRadius(report.report_id, highlight!),
    enabled: !!highlight,
  });

  if (!graph || graph.nodes.length === 0) {
    return (
      <EmptyState
        icon={<Network />}
        title="No dependency graph"
        description="This report has no dependency graph — it was analyzed before graph support, or the content had no linkable infrastructure resources."
      />
    );
  }

  const spofs = graph.spofs;

  return (
    <div className="space-y-6">
      {/* SPOFs */}
      {spofs.length > 0 && (
        <div className="surface-raised rounded-lg border border-danger/25 bg-danger/[0.04] p-4">
          <div className="mb-3 flex items-center gap-2">
            <AlertTriangle className="size-4 text-danger" />
            <h3 className="text-sm font-semibold">
              {spofs.length} single point{spofs.length === 1 ? "" : "s"} of failure
            </h3>
          </div>
          <div className="space-y-2">
            {spofs.map((s) => (
              <div
                key={s.node}
                className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm"
              >
                <span className="font-mono text-xs">{s.node}</span>
                <Badge tone="neutral">{s.dependent_count} dependents</Badge>
                {s.reasons.map((r) => (
                  <Badge key={r} tone="warning">
                    {r}
                  </Badge>
                ))}
                <button
                  onClick={() => setHighlight(s.node)}
                  className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-primary-hover"
                >
                  <Crosshair className="size-3.5" /> Blast radius
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Blast-radius picker */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">Trace blast radius:</span>
        <select
          value={highlight ?? ""}
          onChange={(e) => setHighlight(e.target.value || null)}
          className="h-8 rounded-md border border-input bg-background px-2.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <option value="">Select a resource…</option>
          {graph.nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id}
            </option>
          ))}
        </select>
        {highlight && (
          <button
            onClick={() => setHighlight(null)}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            Clear
          </button>
        )}
      </div>

      {/* Blast-radius result */}
      {highlight && (
        <div className="surface-raised rounded-lg border border-border bg-card p-4">
          {blast.isLoading ? (
            <div className="flex justify-center py-4">
              <Spinner className="text-primary" />
            </div>
          ) : blast.data?.found ? (
            <div className="space-y-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{blast.data.resource}</span>
                <Badge tone={blast.data.is_spof ? "danger" : "neutral"}>
                  {blast.data.criticality}
                </Badge>
                <span className="text-muted-foreground">
                  impacts {blast.data.impact_count} resource
                  {blast.data.impact_count === 1 ? "" : "s"}
                </span>
              </div>
              {blast.data.direct_dependents.length > 0 && (
                <div>
                  <p className="mb-1 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                    Direct dependents
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {blast.data.direct_dependents.map((r) => (
                      <span key={r} className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-2xs">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {blast.data.transitive_dependents.length > 0 && (
                <div>
                  <p className="mb-1 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                    Transitive dependents
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {blast.data.transitive_dependents.map((r) => (
                      <span key={r} className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-2xs text-muted-foreground">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {blast.data.impact_count === 0 && (
                <p className="text-muted-foreground">Nothing depends on this resource.</p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Resource not found in the graph.</p>
          )}
        </div>
      )}

      {/* Diagram */}
      <div>
        <h3 className="mb-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
          Dependency diagram · {graph.nodes.length} nodes · {graph.edges.length} edges
        </h3>
        {diagram.isLoading ? (
          <div className="flex justify-center rounded-lg border border-border py-10">
            <Spinner className="text-primary" />
          </div>
        ) : diagram.data ? (
          <Suspense
            fallback={
              <div className="flex justify-center rounded-lg border border-border py-10">
                <Spinner className="text-primary" />
              </div>
            }
          >
            <Mermaid chart={diagram.data} />
          </Suspense>
        ) : (
          <p className="text-sm text-muted-foreground">Diagram unavailable.</p>
        )}
      </div>
    </div>
  );
}
