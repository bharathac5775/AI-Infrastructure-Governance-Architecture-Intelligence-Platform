import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import type { AnalysisReport } from "@/types/api";
import { useAnalysisRunState, useClearAnalysisRuns } from "@/lib/use-analysis";

// Mounted once in AppShell (which never unmounts on route changes), this watches
// the shared analysis run. When a run finishes successfully it navigates to the
// resulting report — from whatever page the user is on — then clears the run so
// it fires exactly once. This is what makes an analysis survive navigating away
// mid-run: the request completes in the cache, and the watcher (not the now-
// unmounted workspace) delivers the user to the report.
export function RunWatcher() {
  const navigate = useNavigate();
  const run = useAnalysisRunState();
  const clearRuns = useClearAnalysisRuns();
  // Guards against re-navigating for a run we've already handled.
  const handledAt = useRef<number>(0);

  useEffect(() => {
    if (!run || run.isPending || run.isError) return;
    const report = run.data as AnalysisReport | undefined;
    if (!report?.report_id) return;
    if (run.submittedAt === handledAt.current) return;

    handledAt.current = run.submittedAt;
    navigate(`/reports/${report.report_id}`);
    // Clear on the next tick so we don't remove the mutation mid-render.
    queueMicrotask(clearRuns);
  }, [run, navigate, clearRuns]);

  return null;
}
