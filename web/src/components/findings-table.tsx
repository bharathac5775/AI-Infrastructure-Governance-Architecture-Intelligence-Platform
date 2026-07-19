import { useMemo, useState } from "react";
import { Search, ChevronRight, ShieldCheck } from "lucide-react";
import type { AnalysisReport, Finding, Severity } from "@/types/api";
import { Dialog } from "@/components/ui/drawer";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/states";
import { FindingDetail } from "@/components/finding-detail";
import { severityTone, SEVERITY_ORDER } from "@/lib/report-utils";
import { cn } from "@/lib/utils";

// A finding paired with its FLATTENED index across all agent reports (agent
// order preserved) — this index is what the remediation endpoint expects.
interface IndexedFinding {
  finding: Finding;
  index: number;
}

function flattenFindings(report: AnalysisReport): IndexedFinding[] {
  const out: IndexedFinding[] = [];
  let i = 0;
  for (const ar of report.agent_reports) {
    for (const f of ar.findings) {
      out.push({ finding: f, index: i });
      i += 1;
    }
  }
  return out;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function FindingsTable({
  report,
  fileContents,
}: {
  report: AnalysisReport;
  fileContents: Record<string, string>;
}) {
  const all = useMemo(() => flattenFindings(report), [report]);
  const agents = useMemo(
    () => Array.from(new Set(all.map((x) => x.finding.agent))).sort(),
    [all]
  );

  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [selected, setSelected] = useState<IndexedFinding | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all
      .filter((x) => sevFilter === "all" || x.finding.severity === sevFilter)
      .filter((x) => agentFilter === "all" || x.finding.agent === agentFilter)
      .filter(
        (x) =>
          !q ||
          x.finding.title.toLowerCase().includes(q) ||
          x.finding.resource.toLowerCase().includes(q) ||
          x.finding.description.toLowerCase().includes(q)
      )
      .sort((a, b) => SEVERITY_ORDER[a.finding.severity] - SEVERITY_ORDER[b.finding.severity]);
  }, [all, query, sevFilter, agentFilter]);

  if (all.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck />}
        title="No findings"
        description="No governance issues were detected in this configuration."
      />
    );
  }

  return (
    <div>
      {/* Filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-48">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings…"
            className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring placeholder:text-muted-foreground"
          />
        </div>
        <FilterSelect
          value={sevFilter}
          onChange={(v) => setSevFilter(v as Severity | "all")}
          options={[{ value: "all", label: "All severities" }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]}
        />
        <FilterSelect
          value={agentFilter}
          onChange={setAgentFilter}
          options={[{ value: "all", label: "All agents" }, ...agents.map((a) => ({ value: a, label: a }))]}
        />
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface text-left text-2xs font-medium uppercase tracking-wider text-muted-foreground">
              <th className="w-24 px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Finding</th>
              <th className="hidden w-36 px-4 py-2.5 font-medium md:table-cell">Agent</th>
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {filtered.map((x) => (
              <tr
                key={x.index}
                onClick={() => setSelected(x)}
                className="group cursor-pointer border-b border-border last:border-0 transition-colors hover:bg-accent/50"
              >
                <td className="px-4 py-3 align-top">
                  <Badge tone={severityTone(x.finding.severity)} dot>
                    {x.finding.severity}
                  </Badge>
                </td>
                <td className="px-4 py-3.5">
                  <p className="text-[0.9375rem] font-medium leading-snug">{x.finding.title}</p>
                  {x.finding.resource && (
                    <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                      {x.finding.resource}
                    </p>
                  )}
                </td>
                <td className="hidden px-4 py-3 align-top text-muted-foreground md:table-cell">
                  {x.finding.agent}
                </td>
                <td className="px-4 py-3 align-top">
                  <ChevronRight className="size-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-muted-foreground" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-10 text-center text-sm text-muted-foreground">
            No findings match these filters.
          </div>
        )}
      </div>

      <p className="mt-3 text-xs text-muted-foreground">
        Showing {filtered.length} of {all.length} findings
      </p>

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        {selected && (
          <FindingDetail
            reportId={report.report_id}
            finding={selected.finding}
            findingIndex={selected.index}
            fileContents={fileContents}
          />
        )}
      </Dialog>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cn(
        "h-9 rounded-md border border-input bg-background px-3 text-sm capitalize outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring"
      )}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}
