import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { PageHeader } from "@/components/layout/page-header";
import { LoadingState, EmptyState } from "@/components/ui/states";

// Placeholder — full report view (score header, findings, architecture,
// compliance, drift, remediation) lands in Phases 3–4.
export function ReportPage() {
  const { id = "" } = useParams();
  const report = useQuery({
    queryKey: ["report", id],
    queryFn: () => api.getReport(id),
    enabled: !!id,
  });

  if (report.isLoading) return <LoadingState label="Loading report" />;
  if (report.isError || !report.data)
    return (
      <div>
        <PageHeader title="Report" crumbs={[{ label: "Reports", to: "/reports" }, { label: id }]} />
        <EmptyState title="Report not found" />
      </div>
    );

  const r = report.data;
  return (
    <div>
      <PageHeader
        title={`Report ${r.report_id}`}
        crumbs={[{ label: "Reports", to: "/reports" }, { label: r.report_id }]}
        description={`Overall score ${r.overall_score.toFixed(1)} · ${r.files_analyzed.length} file(s)`}
      />
      <EmptyState
        title="Report view coming next"
        description="Findings, architecture, compliance, and drift tabs are built in the next phases."
      />
    </div>
  );
}
