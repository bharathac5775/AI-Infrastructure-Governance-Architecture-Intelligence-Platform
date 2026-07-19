import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { History, Trash2, Download, GitCompareArrows, ArrowRight } from "lucide-react";
import type { CompareResult } from "@/types/api";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/layout/page-header";
import { LoadingState, EmptyState, Spinner } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, Drawer } from "@/components/ui/drawer";
import { scoreTone, formatTimestamp } from "@/lib/report-utils";
import { cn } from "@/lib/utils";

const TONE_TEXT: Record<string, string> = {
  success: "text-success",
  info: "text-info",
  warning: "text-warning",
  danger: "text-danger",
  neutral: "text-foreground",
};

export function ReportsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string[]>([]);
  const [compareOpen, setCompareOpen] = useState(false);

  const reports = useQuery({ queryKey: ["reports"], queryFn: () => api.listReports(100) });

  const del = useMutation({
    mutationFn: (id: string) => api.deleteReport(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const toggleSelect = (id: string) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : prev.length < 2 ? [...prev, id] : [prev[1], id]
    );
  };

  if (reports.isLoading) return <LoadingState label="Loading reports" />;

  const items = reports.data ?? [];

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Every analysis you've run. Select two to compare, or open one for the full report."
        actions={
          selected.length === 2 && (
            <Button variant="primary" onClick={() => setCompareOpen(true)}>
              <GitCompareArrows /> Compare selected
            </Button>
          )
        }
      />

      {items.length === 0 ? (
        <EmptyState
          icon={<History />}
          title="No reports yet"
          description="Run an analysis from the Analyze screen — your reports will appear here."
          action={
            <Button variant="secondary" onClick={() => navigate("/")}>
              Go to Analyze <ArrowRight />
            </Button>
          }
        />
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface text-left text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                <th className="w-10 px-4 py-2.5" />
                <th className="w-20 px-4 py-2.5 font-medium">Score</th>
                <th className="px-4 py-2.5 font-medium">Files</th>
                <th className="hidden w-40 px-4 py-2.5 font-medium sm:table-cell">Analyzed</th>
                <th className="w-24 px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => {
                const tone = scoreTone(r.overall_score);
                const isSel = selected.includes(r.report_id);
                return (
                  <tr
                    key={r.report_id}
                    className={cn(
                      "group border-b border-border last:border-0 transition-colors hover:bg-accent/50",
                      isSel && "bg-primary/[0.06]"
                    )}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={isSel}
                        onChange={() => toggleSelect(r.report_id)}
                        className="size-4 cursor-pointer accent-primary"
                        aria-label={`Select report ${r.report_id}`}
                      />
                    </td>
                    <td
                      className="cursor-pointer px-4 py-3"
                      onClick={() => navigate(`/reports/${r.report_id}`)}
                    >
                      <span className={`text-lg font-semibold tabular ${TONE_TEXT[tone!]}`}>
                        {r.overall_score.toFixed(0)}
                      </span>
                    </td>
                    <td
                      className="cursor-pointer px-4 py-3"
                      onClick={() => navigate(`/reports/${r.report_id}`)}
                    >
                      <p className="font-medium">{r.files_analyzed || "—"}</p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {r.report_id} · {r.file_count} file{r.file_count === 1 ? "" : "s"}
                      </p>
                    </td>
                    <td className="hidden px-4 py-3 text-muted-foreground sm:table-cell">
                      {formatTimestamp(r.timestamp)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                        <a
                          href={api.pdfUrl(r.report_id)}
                          target="_blank"
                          rel="noreferrer"
                          className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                          title="Export PDF"
                        >
                          <Download className="size-4" />
                        </a>
                        <button
                          onClick={() => del.mutate(r.report_id)}
                          disabled={del.isPending}
                          className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-danger/10 hover:text-danger"
                          title="Delete report"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selected.length > 0 && (
        <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
          <span>{selected.length}/2 selected for comparison</span>
          <button onClick={() => setSelected([])} className="hover:text-foreground">
            Clear
          </button>
        </div>
      )}

      <Dialog open={compareOpen} onOpenChange={setCompareOpen}>
        {selected.length === 2 && <CompareDrawer a={selected[0]} b={selected[1]} />}
      </Dialog>
    </div>
  );
}

function CompareDrawer({ a, b }: { a: string; b: string }) {
  const cmp = useQuery({
    queryKey: ["compare", a, b],
    queryFn: () => api.compareReports(a, b),
  });

  return (
    <Drawer title="Compare reports">
      <div className="scrollbar-thin flex-1 overflow-y-auto p-6">
        <h2 className="text-base font-semibold tracking-tight">Compare reports</h2>
        {cmp.isLoading ? (
          <div className="py-10">
            <Spinner className="mx-auto text-primary" />
          </div>
        ) : cmp.isError || !cmp.data ? (
          <p className="mt-4 text-sm text-danger">Could not compare these reports.</p>
        ) : (
          <CompareBody data={cmp.data} />
        )}
      </div>
    </Drawer>
  );
}

function CompareBody({ data }: { data: CompareResult }) {
  const rows: { label: string; delta: number }[] = [
    { label: "Overall", delta: data.overall_delta },
    { label: "Security", delta: data.security_delta },
    { label: "Reliability", delta: data.reliability_delta },
    { label: "Cost", delta: data.cost_delta },
  ];
  return (
    <div className="mt-4 space-y-5">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span className="font-mono">{data.report_a.id}</span>
        <ArrowRight className="size-3.5" />
        <span className="font-mono">{data.report_b.id}</span>
      </div>

      <div className="space-y-2">
        {rows.map((r) => (
          <div
            key={r.label}
            className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2.5"
          >
            <span className="text-sm font-medium">{r.label}</span>
            <DeltaChip delta={r.delta} />
          </div>
        ))}
        <div className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2.5">
          <span className="text-sm font-medium">Findings</span>
          <span
            className={cn(
              "text-sm font-semibold tabular",
              data.findings_delta < 0 ? "text-success" : data.findings_delta > 0 ? "text-danger" : "text-muted-foreground"
            )}
          >
            {data.findings_delta > 0 ? "+" : ""}
            {data.findings_delta}
          </span>
        </div>
      </div>
    </div>
  );
}

function DeltaChip({ delta }: { delta: number }) {
  const tone = delta > 0 ? "success" : delta < 0 ? "danger" : "neutral";
  return (
    <Badge tone={tone}>
      {delta > 0 ? "+" : ""}
      {delta.toFixed(1)}
    </Badge>
  );
}
