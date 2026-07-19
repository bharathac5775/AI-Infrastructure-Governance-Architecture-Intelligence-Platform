import type { Finding } from "@/types/api";

// Faithful TypeScript port of the frontend patchability gate in
// frontend/app.py (Phase 3.4/3.5). A finding is "advisory" (no Generate-fix
// button) when it cannot be fixed by a code patch. Keeping this identical to
// the Streamlit logic means the two frontends agree on what's fixable, and it
// matches the backend's NonPatchableFinding categories.

const NON_PATCHABLE_RESOURCE = new Set([
  "",
  "n/a",
  "na",
  "none",
  "null",
  "-",
  "infrastructure",
  "all",
  "global",
  "various",
  "multiple",
]);

const FILE_EXTS = [".yaml", ".yml", ".json", ".tf", ".hcl", ".tgz"];

const ADVISORY_VERBS = [
  "analyze",
  "monitor",
  "consider",
  "evaluate",
  "review",
  "determine",
  "investigate",
  "audit",
  "assess",
  "maintain",
  "continue",
  "keep",
];

const NO_ACTION_PHRASES = [
  "no immediate action",
  "no action",
  "no change",
  "no changes",
  "no fix",
  "this is already",
  "this is a recommended",
  "this is best practice",
  "this is correct",
  "this is the recommended",
  "already configured",
  "already enabled",
  "already in place",
  "already meets",
  "already follows",
  "the current configuration is correct",
  "the configuration is already",
];

export type AdvisoryKind =
  | "rollup"
  | "resilience"
  | "path"
  | "advisory-praise"
  | "advisory-decision"
  | "advisory-scope"
  | null;

export interface Patchability {
  patchable: boolean;
  kind: AdvisoryKind;
  /** Human-readable reason shown when not patchable. */
  note: string;
  /** For advisory-decision: the leading verb, for the message. */
  verb?: string;
}

function looksLikePath(resourceLower: string): boolean {
  if (FILE_EXTS.some((e) => resourceLower.endsWith(e))) return true;
  if (resourceLower.includes("/templates/")) return true;
  // LLM "deployment.yaml (chart-name)" annotated form
  if (
    !resourceLower.endsWith(")") ||
    !resourceLower.includes(" (")
  ) {
    return false;
  }
  const prefix = resourceLower.split(" (", 1)[0]?.trim() ?? "";
  return FILE_EXTS.some((e) => prefix.endsWith(e)) || prefix.includes("/templates/");
}

export function getPatchability(finding: Finding): Patchability {
  const resourceStr = String(finding.resource ?? "").trim();
  const resourceLower = resourceStr.toLowerCase();
  const rec = String(finding.recommendation ?? "").trim();
  const recLower = rec.toLowerCase();
  const firstWord = rec ? rec.split(/\s+/)[0].replace(/^[.,:;]+|[.,:;]+$/g, "").toLowerCase() : "";

  const isRollup = finding.category === "compliance-gap";
  const isResilience = finding.category === "resilience";
  const isPath = looksLikePath(resourceLower);
  const isAdvisoryLang =
    finding.category === "ai-analysis" &&
    (ADVISORY_VERBS.includes(firstWord) ||
      NO_ACTION_PHRASES.some((p) => recLower.startsWith(p)));
  const isScope = NON_PATCHABLE_RESOURCE.has(resourceLower);

  if (isRollup)
    return {
      patchable: false,
      kind: "rollup",
      note: "Compliance roll-up — this summarizes other findings against a framework, so there is nothing to patch here. Generate fixes on the underlying Security / Reliability / Cost findings mapped to the failing controls; the framework score rises as those are resolved.",
    };
  if (isResilience)
    return {
      patchable: false,
      kind: "resilience",
      note: "Architectural finding (single point of failure) — a design observation, not a config defect, so there's nothing to auto-patch. Address it by adding redundancy (replicas / Multi-AZ / a standby) or decoupling the dependents shown in the Architecture tab.",
    };
  if (isPath)
    return {
      patchable: false,
      kind: "path",
      note: `Resource "${resourceStr}" looks like a file or template path, not a runtime resource — no automatic patch available.`,
    };
  if (isAdvisoryLang) {
    if (NO_ACTION_PHRASES.some((p) => recLower.startsWith(p)))
      return {
        patchable: false,
        kind: "advisory-praise",
        note: "No action needed — this finding praises an already-correct configuration. Nothing to patch.",
      };
    const verb = rec ? rec.split(/\s+/)[0] : "Advisory";
    return {
      patchable: false,
      kind: "advisory-decision",
      verb,
      note: `Advisory finding — its recommendation starts with "${verb}…", meaning it asks you to evaluate or make a decision rather than apply a specific code change. Not auto-remediable.`,
    };
  }
  if (isScope)
    return {
      patchable: false,
      kind: "advisory-scope",
      note: "Advisory finding — describes a whole-infrastructure or purchasing decision; no automatic patch available.",
    };

  return { patchable: true, kind: null, note: "" };
}
