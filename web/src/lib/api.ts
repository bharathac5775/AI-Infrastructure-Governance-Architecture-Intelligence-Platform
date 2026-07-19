import type {
  AnalysisReport,
  BlastRadius,
  DriftResponse,
  HealthResponse,
  Patch,
  ReportListItem,
} from "@/types/api";

// Single fetch wrapper. All calls go through /api (proxied to FastAPI in dev,
// served same-origin in prod). Throws ApiError with the backend's detail so the
// UI can distinguish 409 companion / 409 non-patchable / 422 remediation-failed.

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown, message: string) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    const detail =
      body && typeof body === "object" && "detail" in (body as object)
        ? (body as { detail: unknown }).detail
        : body;
    const msg =
      typeof detail === "string"
        ? detail
        : detail && typeof detail === "object" && "message" in (detail as object)
          ? String((detail as { message: unknown }).message)
          : `Request failed (${res.status})`;
    throw new ApiError(res.status, detail, msg);
  }
  return body as T;
}

export const api = {
  health: () => request<HealthResponse>("/health"),

  analyzeFiles: (files: File[]) => {
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f));
    return request<AnalysisReport>("/analyze", { method: "POST", body: fd });
  },

  analyzeText: (fileContents: Record<string, string>, analysisTypes?: string[]) =>
    request<AnalysisReport>("/analyze/text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_contents: fileContents,
        analysis_types: analysisTypes ?? ["security", "reliability", "cost"],
      }),
    }),

  getReport: (id: string) => request<AnalysisReport>(`/reports/${id}`),

  listReports: (limit = 50) => request<ReportListItem[]>(`/reports?limit=${limit}`),

  deleteReport: (id: string) =>
    request<{ status: string; report_id: string }>(`/reports/${id}`, { method: "DELETE" }),

  compareReports: (a: string, b: string) =>
    request<Record<string, unknown>>(`/reports/compare/${a}/${b}`),

  similarReports: (id: string, n = 3) =>
    request<Record<string, unknown>>(`/reports/${id}/similar?n=${n}`),

  drift: (id: string) => request<DriftResponse>(`/reports/${id}/drift`),

  blastRadius: (id: string, resource: string) =>
    request<BlastRadius>(
      `/reports/${id}/blast-radius?resource=${encodeURIComponent(resource)}`
    ),

  diagram: (id: string, highlight?: string) => {
    const q = highlight ? `&highlight=${encodeURIComponent(highlight)}` : "";
    return fetch(`${BASE}/reports/${id}/diagram?format=mermaid${q}`).then((r) => {
      if (!r.ok) throw new ApiError(r.status, null, "Diagram unavailable");
      return r.text();
    });
  },

  pdfUrl: (id: string) => `${BASE}/reports/${id}/export/pdf`,

  remediate: (id: string, findingIndex: number, fileContents: Record<string, string>) =>
    request<Patch>(`/reports/${id}/remediate/${findingIndex}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_contents: fileContents }),
    }),
};
