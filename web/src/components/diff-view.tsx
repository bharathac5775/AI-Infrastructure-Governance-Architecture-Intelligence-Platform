import { cn } from "@/lib/utils";

// Minimal unified-diff renderer: colorizes +/- lines and dims @@ hunks. No
// syntax highlighting — the diff structure is what matters for a patch review.
export function DiffView({ diff }: { diff: string }) {
  const lines = diff.split("\n");
  return (
    <pre className="scrollbar-thin max-h-96 overflow-auto rounded-lg border border-border bg-surface p-0 font-mono text-xs leading-relaxed">
      <code className="block">
        {lines.map((line, i) => {
          const isAdd = line.startsWith("+") && !line.startsWith("+++");
          const isDel = line.startsWith("-") && !line.startsWith("---");
          const isHunk = line.startsWith("@@");
          const isMeta =
            line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff");
          return (
            <div
              key={i}
              className={cn(
                "px-3 py-px",
                isAdd && "bg-success/10 text-success",
                isDel && "bg-danger/10 text-danger",
                isHunk && "bg-info/10 text-info",
                isMeta && "text-muted-foreground"
              )}
            >
              {line || " "}
            </div>
          );
        })}
      </code>
    </pre>
  );
}
