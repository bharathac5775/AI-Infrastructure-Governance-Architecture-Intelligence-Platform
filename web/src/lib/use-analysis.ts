import { useMutation, useMutationState, useQueryClient } from "@tanstack/react-query";
import type { AnalysisReport } from "@/types/api";
import { api } from "@/lib/api";

// A single, app-wide analysis run lives under this mutation key. Because the
// mutation is keyed and cached by the QueryClient (not the component), its
// pending/success/error state SURVIVES navigating away from the Analyze page
// and back — the component can unmount and remount without losing the run.
export const ANALYSIS_MUTATION_KEY = ["analyze"] as const;

export interface AnalyzePayload {
  files?: File[];
  text?: { name: string; body: string };
}

// The mutation function, shared by the workspace (which starts runs) and the
// watcher (which reacts to completion). Kept out of the component so both call
// sites register the SAME mutationKey against the SAME options.
function runAnalysis(payload: AnalyzePayload): Promise<AnalysisReport> {
  return payload.files
    ? api.analyzeFiles(payload.files)
    : api.analyzeText({ [payload.text!.name]: payload.text!.body });
}

// Starts/controls an analysis run. Any component that calls this shares one
// underlying mutation instance via the key. gcTime is generous so a run that
// finishes while the user is on another page isn't garbage-collected before
// the watcher navigates to its report.
export function useRunAnalysis() {
  return useMutation({
    mutationKey: ANALYSIS_MUTATION_KEY,
    mutationFn: runAnalysis,
    gcTime: 5 * 60_000,
  });
}

export interface AnalysisRunState {
  isPending: boolean;
  isError: boolean;
  error: unknown;
  data: AnalysisReport | undefined;
  submittedAt: number;
}

// Read-only view of the current/last analysis run, sourced from the mutation
// cache so it's identical no matter which component (or page) is mounted.
// Returns null when no run has ever been started this session.
export function useAnalysisRunState(): AnalysisRunState | null {
  const states = useMutationState({
    filters: { mutationKey: ANALYSIS_MUTATION_KEY },
    select: (m) => ({
      status: m.state.status,
      error: m.state.error,
      data: m.state.data as AnalysisReport | undefined,
      submittedAt: m.state.submittedAt ?? 0,
    }),
  });
  if (states.length === 0) return null;
  // The most recently submitted run is the one we care about.
  const latest = states.reduce((a, b) => (b.submittedAt >= a.submittedAt ? b : a));
  return {
    isPending: latest.status === "pending",
    isError: latest.status === "error",
    error: latest.error,
    data: latest.data,
    submittedAt: latest.submittedAt,
  };
}

// Clears finished analysis mutations from the cache. Call after the watcher has
// navigated to a completed report so a later visit to Analyze starts clean and
// the watcher doesn't re-fire on the same result.
export function useClearAnalysisRuns() {
  const qc = useQueryClient();
  return () => {
    qc.getMutationCache()
      .findAll({ mutationKey: ANALYSIS_MUTATION_KEY })
      .forEach((m) => qc.getMutationCache().remove(m));
  };
}
