import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Wrench,
  Info,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  FileWarning,
} from "lucide-react";
import type { Finding, Patch } from "@/types/api";
import { api, ApiError } from "@/lib/api";
import { getPatchability } from "@/lib/patchability";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/states";
import { DiffView } from "@/components/diff-view";

interface CompanionDetail {
  kind: "companion_resource_required";
  message: string;
  template: string;
  filename: string;
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? <Check className="text-success" /> : <Copy />}
      {copied ? "Copied" : label}
    </Button>
  );
}

// The remediation surface for a single finding. Reproduces the backend's error
// contract: 409 companion_resource_required (render template), 409 non-patchable
// (soft info), 422 remediation failure (error). Requires the report's original
// file_contents — absent on reports loaded from history.
export function RemediationPanel({
  reportId,
  findingIndex,
  finding,
  fileContents,
}: {
  reportId: string;
  findingIndex: number;
  finding: Finding;
  fileContents: Record<string, string>;
}) {
  const patchability = getPatchability(finding);
  const hasFiles = Object.keys(fileContents).length > 0;

  const remediate = useMutation<Patch, ApiError>({
    mutationFn: () => api.remediate(reportId, findingIndex, fileContents),
  });

  // --- Advisory: no fix button, show the reason ---------------------------
  if (!patchability.patchable) {
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-border bg-surface px-3.5 py-3 text-sm text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0 text-info" />
        <span>{patchability.note}</span>
      </div>
    );
  }

  // --- Files unavailable (report loaded from history) ---------------------
  if (!hasFiles) {
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-warning/25 bg-warning/[0.07] px-3.5 py-3 text-sm text-warning">
        <FileWarning className="mt-0.5 size-4 shrink-0" />
        <span>
          Original files aren't cached for this report. Re-run the analysis from the Analyze
          screen to enable one-click fixes.
        </span>
      </div>
    );
  }

  const err = remediate.error;
  const isCompanion =
    err?.status === 409 &&
    err.detail &&
    typeof err.detail === "object" &&
    (err.detail as CompanionDetail).kind === "companion_resource_required";
  const companion = isCompanion ? (err!.detail as CompanionDetail) : null;
  const isNonPatchable = err?.status === 409 && !isCompanion;
  const patch = remediate.data;

  return (
    <div className="space-y-4">
      {!patch && !companion && (
        <Button variant="primary" onClick={() => remediate.mutate()} disabled={remediate.isPending}>
          {remediate.isPending ? <Spinner /> : <Wrench />}
          {remediate.isPending ? "Generating fix…" : "Generate fix"}
        </Button>
      )}

      {/* 409 non-patchable — soft informational */}
      {isNonPatchable && (
        <div className="flex items-start gap-2.5 rounded-lg border border-border bg-surface px-3.5 py-3 text-sm text-muted-foreground">
          <Info className="mt-0.5 size-4 shrink-0 text-info" />
          <span>{err!.message}</span>
        </div>
      )}

      {/* 422 / 500 — genuine failure */}
      {err && !isCompanion && !isNonPatchable && (
        <div className="flex items-start gap-2.5 rounded-lg border border-danger/25 bg-danger/[0.07] px-3.5 py-3 text-sm text-danger">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{err.message}</span>
        </div>
      )}

      {/* 409 companion resource required — render the template to copy */}
      {companion && (
        <div className="space-y-3">
          <div className="flex items-start gap-2.5 rounded-lg border border-info/25 bg-info/[0.07] px-3.5 py-3 text-sm text-info">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>{companion.message}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-muted-foreground">{companion.filename}</span>
            <CopyButton text={companion.template} label="Copy template" />
          </div>
          <pre className="scrollbar-thin max-h-72 overflow-auto rounded-lg border border-border bg-surface p-3 font-mono text-xs leading-relaxed">
            {companion.template}
          </pre>
        </div>
      )}

      {/* Success — show the patch */}
      {patch && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="success" dot>
              Fix generated
            </Badge>
            <Badge tone="neutral">{patch.strategy}</Badge>
            {patch.validation_status === "valid" && (
              <span className="flex items-center gap-1 text-xs text-success">
                <CheckCircle2 className="size-3.5" /> Re-parses cleanly
              </span>
            )}
          </div>

          <p className="text-sm text-muted-foreground">{patch.explanation}</p>

          {patch.warnings.length > 0 && (
            <ul className="space-y-1 rounded-lg border border-warning/25 bg-warning/[0.06] px-3.5 py-2.5 text-xs text-warning">
              {patch.warnings.map((w, i) => (
                <li key={i} className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 size-3 shrink-0" />
                  {w}
                </li>
              ))}
            </ul>
          )}

          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-muted-foreground">{patch.filename}</span>
            <CopyButton text={patch.patched_content} label="Copy patched file" />
          </div>
          <DiffView diff={patch.unified_diff} />
        </div>
      )}
    </div>
  );
}
