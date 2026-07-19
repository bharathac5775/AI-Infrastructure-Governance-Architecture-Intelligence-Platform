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

  return (
    <div>
      <PageHeader
        title={`Report ${r.report_id}`}
        crumbs={[{ label: "Reports", to: "/reports" }, { label: r.report_id }]}
        description={`${r.files_analyzed.length} file${r.files_analyzed.length === 1 ? "" : "s"} · ${formatTimestamp(r.timestamp)}`}
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
          <FindingsTable report={r} />
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
