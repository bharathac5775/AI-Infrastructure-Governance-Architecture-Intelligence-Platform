import { ArrowDown, ShieldCheck, Layers, Wrench, FileBarChart, GitBranch, Wand2 } from "lucide-react";
import { AnalyzeWorkspace } from "@/components/analyze-workspace";
import { AGENTS, STEPS, CAPABILITIES } from "@/lib/product-copy";

// Concrete deliverables of a single analysis — describes what the product
// produces, not how it runs. Each maps to a real report section.
const OUTCOMES = [
  {
    icon: FileBarChart,
    title: "A scored governance report",
    body: "A weighted overall score with per-agent breakdowns and findings ranked by severity — so you know what to fix first, not just what's wrong.",
  },
  {
    icon: GitBranch,
    title: "A dependency & risk map",
    body: "A graph of how your resources connect, with single points of failure flagged and the blast radius of each component made explicit.",
  },
  {
    icon: Wand2,
    title: "Fixes you can apply",
    body: "Findings come with concrete remediation — deterministic patches where possible, plus compliance scorecards and an auditor-ready PDF.",
  },
] as const;

// The home screen IS the analyze screen — but it opens by explaining the
// product (hero → what the agents do → how it works) before presenting the
// upload workspace. First-time visitors understand it; returning users scroll
// to the tool. Every claim maps to a shipped backend capability.
export function AnalyzePage() {
  return (
    <div className="space-y-16 pb-8">
      {/* ---- Hero ---------------------------------------------------------- */}
      <section className="relative overflow-hidden pt-6">
        <div className="pointer-events-none absolute inset-x-0 -top-8 h-56 bg-dotted opacity-[0.5] [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]" />
        <div className="relative max-w-2xl">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs font-medium text-muted-foreground surface-raised">
            <span className="flex size-1.5 rounded-full bg-primary" />
            Multi-agent infrastructure governance
          </div>
          <h1 className="text-balance text-4xl font-semibold leading-[1.1] tracking-tight sm:text-[2.75rem]">
            Govern your infrastructure
            <br />
            <span className="text-muted-foreground">before it ships.</span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-relaxed text-muted-foreground">
            Six specialized agents review your Terraform, Kubernetes, and Helm
            configuration in a single pass — scoring it for security,
            reliability, cost, architecture, compliance, and resilience. You get
            a weighted governance score, findings ranked by severity, a
            dependency map of what could break, and code-level fixes you can
            apply directly.
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Layers className="size-3.5 text-primary" /> 6 formats · one review
            </span>
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="size-3.5 text-primary" /> CIS-aligned scoring
            </span>
            <span className="flex items-center gap-1.5">
              <Wrench className="size-3.5 text-primary" /> Actionable remediation
            </span>
          </div>
          <a
            href="#analyze"
            className="mt-8 inline-flex items-center gap-2 text-sm font-medium text-primary transition-colors hover:text-primary-hover"
          >
            Start an analysis <ArrowDown className="size-4" />
          </a>
        </div>
      </section>

      {/* ---- What the agents do ------------------------------------------- */}
      <section>
        <div className="mb-6">
          <h2 className="text-lg font-semibold tracking-tight">Six agents, one pass</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Each agent owns a governance dimension and contributes to your overall score.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {AGENTS.map(({ name, icon: Icon, blurb, checks }) => (
            <div
              key={name}
              className="group surface-raised rounded-lg border border-border bg-card p-4 transition-all duration-175 ease-smooth hover:border-border-strong"
            >
              <div className="mb-3 flex size-9 items-center justify-center rounded-lg border border-border bg-surface text-muted-foreground transition-colors group-hover:border-primary/30 group-hover:text-primary">
                <Icon className="size-4" />
              </div>
              <h3 className="text-sm font-semibold">{name}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{blurb}</p>
              <p className="mt-3 border-t border-border pt-2.5 text-2xs font-medium uppercase tracking-wide text-muted-foreground/80">
                {checks}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- How it works ------------------------------------------------- */}
      <section>
        <div className="mb-6">
          <h2 className="text-lg font-semibold tracking-tight">How it works</h2>
        </div>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
          {STEPS.map((step, i) => (
            <div key={step.title} className="relative">
              <div className="mb-3 flex size-7 items-center justify-center rounded-full border border-border bg-card text-xs font-semibold tabular text-primary">
                {i + 1}
              </div>
              <h3 className="text-sm font-semibold">{step.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{step.body}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 flex flex-wrap gap-2">
          {CAPABILITIES.map((c) => (
            <span
              key={c}
              className="rounded-md border border-border bg-surface px-2.5 py-1 text-xs text-muted-foreground"
            >
              {c}
            </span>
          ))}
        </div>
      </section>

      {/* ---- What you get -------------------------------------------------- */}
      <section>
        <div className="mb-6">
          <h2 className="text-lg font-semibold tracking-tight">What every report gives you</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            One analysis produces a complete governance picture, not just a list of warnings.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {OUTCOMES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="surface-raised rounded-lg border border-border bg-card p-5">
              <Icon className="size-5 text-primary" />
              <h3 className="mt-3 text-sm font-semibold">{title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- The workspace ------------------------------------------------ */}
      <section id="analyze" className="scroll-mt-6">
        <div className="mb-6 border-t border-border pt-10">
          <h2 className="text-xl font-semibold tracking-tight">Analyze infrastructure</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Upload files or paste content to run the review. Results open as a scored report.
          </p>
        </div>
        <AnalyzeWorkspace />
      </section>
    </div>
  );
}
