import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FileText, Download, ArrowLeft, FileJson } from "lucide-react";
import type { AnalysisReport } from "@/types/api";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/layout/page-header";
import { LoadingState, EmptyState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScoreHeader } from "@/components/score-header";
import { FindingsTable } from "@/components/findings-table";
import { ArchitecturePanel } from "@/components/architecture-panel";
import { CompliancePanel } from "@/components/compliance-panel";
import { DriftPanel } from "@/components/drift-panel";
import { ReuploadPanel } from "@/components/reupload-panel";
import { formatTimestamp } from "@/lib/report-utils";

// Client-side JSON export: serialize the report the API already returned and
// trigger a browser download. No backend round-trip needed. file_contents is
// stripped so the download matches what the backend persists.
function downloadJson(report: AnalysisReport) {
  const { file_contents: _drop, ...rest } = report;
  const blob = new Blob([JSON.stringify(rest, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `governance-report-${report.report_id}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function ReportPage() {
  const { id = "" } = useParams();
  const report = useQuery({
    queryKey: ["report", id],
    queryFn: () => api.getReport(id),
    enabled: !!id,
  });
  // Files re-uploaded in-browser for a history report that has no cached
  // contents. Merged with the report's own file_contents below and passed to
  // the findings table so remediation works without a fresh analysis.
  const [reuploaded, setReuploaded] = useState<Record<string, string>>({});

  if (report.isLoading) return <LoadingState label="Loading report" />;
  if (report.isError || !report.data) {
    return (
      <div>
        <PageHeader
          title="Report"
          crumbs={[{ label: "Reports", to: "/reports" }, { label: id }]}
        />
        <EmptyState
          icon={<FileText />}
          title="Report not found"
          description="This report may have been deleted, or the link is out of date."
          action={
            <Button variant="secondary" asChild>
              <Link to="/">
                <ArrowLeft /> Back to Analyze
              </Link>
            </Button>
          }
        />
      </div>
    );
  }

  const r = report.data;
  const findingCount = r.agent_reports.reduce((n, a) => n + a.findings.length, 0);
  const spofCount = r.dependency_graph?.spofs.length ?? 0;
  const frameworkCount = r.compliance?.frameworks.length ?? 0;

  // Effective file contents = whatever the report shipped with, plus anything
  // re-uploaded in this session. Remediation reads from this.
  const effectiveContents = { ...(r.file_contents ?? {}), ...reuploaded };
  const needsReupload = Object.keys(effectiveContents).length === 0 && r.files_analyzed.length > 0;

  // Show the actual file(s) in the heading — more meaningful than the ID alone.
  const fileTitle =
    r.files_analyzed.length === 0
      ? `Report ${r.report_id}`
      : r.files_analyzed.length === 1
        ? r.files_analyzed[0]
        : `${r.files_analyzed[0]} + ${r.files_analyzed.length - 1} more`;

  return (
    <div>
      <PageHeader
        title={fileTitle}
        crumbs={[{ label: "Reports", to: "/reports" }, { label: r.report_id }]}
        description={`Report ${r.report_id} · ${r.files_analyzed.length} file${r.files_analyzed.length === 1 ? "" : "s"} · ${formatTimestamp(r.timestamp)}`}
        actions={
          <>
            <Button variant="secondary" onClick={() => downloadJson(r)}>
              <FileJson /> Download JSON
            </Button>
            <Button variant="secondary" asChild>
              <a href={api.pdfUrl(r.report_id)} target="_blank" rel="noreferrer">
                <Download /> Export PDF
              </a>
            </Button>
          </>
        }
      />

      <div className="mb-8">
        <ScoreHeader report={r} />
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            Findings
            <span className="ml-1 rounded bg-secondary px-1.5 py-0.5 text-2xs tabular text-muted-foreground">
              {findingCount}
            </span>
          </TabsTrigger>
          <TabsTrigger value="architecture">
            Architecture
            {spofCount > 0 && (
              <span className="ml-1 rounded bg-danger/15 px-1.5 py-0.5 text-2xs tabular text-danger">
                {spofCount}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="compliance">
            Compliance
            {frameworkCount > 0 && (
              <span className="ml-1 rounded bg-secondary px-1.5 py-0.5 text-2xs tabular text-muted-foreground">
                {frameworkCount}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="drift">Drift</TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          {needsReupload && (
            <div className="mb-4">
              <ReuploadPanel
                neededFiles={r.files_analyzed}
                provided={reuploaded}
                onFiles={(contents) =>
                  setReuploaded((prev) =>
                    Object.keys(contents).length === 0 ? {} : { ...prev, ...contents }
                  )
                }
              />
            </div>
          )}
          <FindingsTable report={r} fileContents={effectiveContents} />
        </TabsContent>
        <TabsContent value="architecture">
          <ArchitecturePanel report={r} />
        </TabsContent>
        <TabsContent value="compliance">
          <CompliancePanel report={r} />
        </TabsContent>
        <TabsContent value="drift">
          <DriftPanel reportId={r.report_id} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
