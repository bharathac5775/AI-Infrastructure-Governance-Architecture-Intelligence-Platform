import type { Finding } from "@/types/api";
import { Drawer } from "@/components/ui/drawer";
import { Badge } from "@/components/ui/badge";
import { RemediationPanel } from "@/components/remediation-panel";
import { severityTone } from "@/lib/report-utils";
import { agentVisual } from "@/lib/product-copy";
import { cn } from "@/lib/utils";

// Slide-in detail for one finding: full description, recommendation, compliance
// mappings, and the remediation surface.
export function FindingDetail({
  reportId,
  finding,
  findingIndex,
  fileContents,
}: {
  reportId: string;
  finding: Finding;
  findingIndex: number;
  fileContents: Record<string, string>;
}) {
  return (
    <Drawer title={finding.title}>
      <div className="scrollbar-thin flex-1 overflow-y-auto">
        <div className="border-b border-border p-6">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge tone={severityTone(finding.severity)} dot>
              {finding.severity}
            </Badge>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface py-0.5 pl-1 pr-2 text-xs font-medium text-muted-foreground">
              {(() => {
                const v = agentVisual(finding.agent);
                const Icon = v.icon;
                return (
                  <span className={cn("flex size-4 items-center justify-center rounded", v.tile)}>
                    <Icon className={cn("size-3", v.fg)} />
                  </span>
                );
              })()}
              {finding.agent}
            </span>
            <Badge tone="neutral">{finding.category}</Badge>
          </div>
          <h2 className="pr-8 text-base font-semibold leading-snug tracking-tight">
            {finding.title}
          </h2>
          {finding.resource && (
            <p className="mt-2 font-mono text-xs text-muted-foreground">{finding.resource}</p>
          )}
        </div>

        <div className="space-y-6 p-6">
          <section>
            <h3 className="mb-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
              Description
            </h3>
            <p className="text-sm leading-relaxed">{finding.description}</p>
          </section>

          <section>
            <h3 className="mb-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
              Recommendation
            </h3>
            <p className="text-sm leading-relaxed">{finding.recommendation}</p>
          </section>

          {finding.compliance_controls.length > 0 && (
            <section>
              <h3 className="mb-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
                Compliance controls
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {finding.compliance_controls.map((c) => (
                  <Badge key={c} tone="primary">
                    {c}
                  </Badge>
                ))}
              </div>
            </section>
          )}

          <section>
            <h3 className="mb-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground">
              Remediation
            </h3>
            <RemediationPanel
              reportId={reportId}
              findingIndex={findingIndex}
              finding={finding}
              fileContents={fileContents}
            />
          </section>
        </div>
      </div>
    </Drawer>
  );
}
