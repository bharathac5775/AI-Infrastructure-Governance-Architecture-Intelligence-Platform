import { useEffect, useId, useRef, useState } from "react";
import mermaid from "mermaid";
import { useTheme } from "@/components/theme-provider";
import { Spinner } from "@/components/ui/states";

// Renders a Mermaid diagram natively (no iframe). Re-initializes on theme change
// so the diagram matches light/dark. Errors render as a readable message rather
// than throwing — a malformed graph shouldn't blank the page.
export function Mermaid({ chart }: { chart: string }) {
  const { resolved } = useTheme();
  const id = useId().replace(/:/g, "");
  const ref = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    mermaid.initialize({
      startOnLoad: false,
      theme: resolved === "dark" ? "dark" : "neutral",
      securityLevel: "strict",
      flowchart: { curve: "basis", useMaxWidth: true },
      fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
    });

    mermaid
      .render(`mmd-${id}`, chart)
      .then(({ svg }) => {
        if (cancelled) return;
        if (ref.current) ref.current.innerHTML = svg;
        setLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to render diagram");
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [chart, resolved, id]);

  if (error) {
    return (
      <div className="rounded-lg border border-danger/25 bg-danger/[0.06] p-4 text-sm text-danger">
        Could not render the diagram: {error}
      </div>
    );
  }

  return (
    <div className="scrollbar-thin overflow-auto rounded-lg border border-border bg-card p-4 surface-raised">
      {loading && (
        <div className="flex justify-center py-8">
          <Spinner className="size-5 text-primary" />
        </div>
      )}
      <div ref={ref} className={loading ? "hidden" : "[&_svg]:mx-auto [&_svg]:h-auto [&_svg]:max-w-full"} />
    </div>
  );
}
