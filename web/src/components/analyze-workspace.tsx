import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileCode2, X, ClipboardType, AlertCircle } from "lucide-react";
import { ApiError } from "@/lib/api";
import { useRunAnalysis, useAnalysisRunState } from "@/lib/use-analysis";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Spinner } from "@/components/ui/states";
import { cn } from "@/lib/utils";

const ACCEPT = ".yaml,.yml,.tf,.json,.hcl,.tgz";
const ACCEPT_LABEL = "YAML · TF · JSON · HCL · TGZ";

// The working surface: upload dropzone + VS Code-style paste editor, wired to
// the real /analyze endpoints. Extracted from the page so the home screen can
// compose an explanatory hero above it.
//
// The run itself is owned by a shared, keyed mutation (useRunAnalysis) so it
// survives navigating away and back — the "Analyzing…" state and auto-navigate
// come from the cache (useAnalysisRunState + the RunWatcher in AppShell), not
// from this component's lifetime.
export function AnalyzeWorkspace() {
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [pasteName, setPasteName] = useState("main.tf");
  const [pasteBody, setPasteBody] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const analyze = useRunAnalysis();
  // Pending/error come from the cache so a remount after navigation still
  // reflects an in-flight run started before we left the page.
  const run = useAnalysisRunState();
  const isPending = run?.isPending ?? false;

  const addFiles = useCallback((incoming: FileList | File[]) => {
    const arr = Array.from(incoming);
    setFiles((prev) => {
      const seen = new Set(prev.map((f) => f.name));
      return [...prev, ...arr.filter((f) => !seen.has(f.name))];
    });
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files);
    },
    [addFiles]
  );

  const errMsg =
    run?.isError && run.error instanceof ApiError
      ? run.error.message
      : run?.isError
        ? "Analysis failed. Is the API running?"
        : null;

  return (
    <Tabs defaultValue="upload">
      <TabsList>
        <TabsTrigger value="upload">
          <UploadCloud className="size-4" /> Upload files
        </TabsTrigger>
        <TabsTrigger value="paste">
          <ClipboardType className="size-4" /> Paste content
        </TabsTrigger>
      </TabsList>

      <TabsContent value="upload">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
          className={cn(
            "group relative flex cursor-pointer flex-col items-center justify-center gap-4 overflow-hidden rounded-xl border border-dashed px-6 py-14 text-center transition-all duration-200 ease-smooth",
            dragging
              ? "border-primary bg-primary/[0.04] ring-4 ring-primary/10"
              : "border-border-strong hover:border-primary/50 hover:bg-accent/40"
          )}
        >
          <div className="pointer-events-none absolute inset-0 bg-dotted opacity-40" />
          <div
            className={cn(
              "relative flex size-12 items-center justify-center rounded-xl border border-border bg-card text-muted-foreground transition-all duration-200 ease-smooth",
              dragging
                ? "scale-110 border-primary/40 text-primary"
                : "group-hover:border-primary/30 group-hover:text-primary"
            )}
          >
            <UploadCloud className="size-5" />
          </div>
          <div className="relative space-y-1">
            <p className="text-sm font-medium">
              {dragging ? "Drop to upload" : "Drop files here, or click to browse"}
            </p>
            <p className="text-xs text-muted-foreground">{ACCEPT_LABEL}</p>
          </div>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ACCEPT}
            className="hidden"
            onChange={(e) => e.target.files && addFiles(e.target.files)}
          />
        </div>

        {files.length > 0 && (
          <div className="mt-4 space-y-2 animate-fade-in-up">
            <p className="text-2xs font-medium uppercase tracking-wider text-muted-foreground">
              {files.length} file{files.length > 1 ? "s" : ""} queued
            </p>
            <div className="flex flex-wrap gap-2">
              {files.map((f) => (
                <span
                  key={f.name}
                  className="group inline-flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-xs transition-colors hover:border-border-strong"
                >
                  <FileCode2 className="size-3.5 text-muted-foreground" />
                  <span className="font-medium">{f.name}</span>
                  <span className="text-2xs tabular text-muted-foreground">
                    {(f.size / 1024).toFixed(1)} KB
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFiles((prev) => prev.filter((x) => x.name !== f.name));
                    }}
                    className="text-muted-foreground transition-colors hover:text-danger"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="size-3.5" />
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="mt-6 flex items-center gap-3">
          <Button
            variant="primary"
            disabled={files.length === 0 || isPending}
            onClick={() => analyze.mutate({ files })}
          >
            {isPending && <Spinner />}
            {isPending ? "Analyzing…" : "Run analysis"}
          </Button>
          {files.length > 0 && (
            <Button variant="ghost" onClick={() => setFiles([])} disabled={isPending}>
              Clear
            </Button>
          )}
        </div>
      </TabsContent>

      <TabsContent value="paste">
        {/* VS Code–style editor chrome: window dots, filename tab, gutter. */}
        <div className="overflow-hidden rounded-lg border border-border-strong bg-card surface-raised">
          <div className="flex items-center gap-3 border-b border-border bg-surface px-3 py-2">
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-danger/70" />
              <span className="size-2.5 rounded-full bg-warning/70" />
              <span className="size-2.5 rounded-full bg-success/70" />
            </div>
            <div className="flex items-center gap-2 rounded-t-md border border-b-0 border-border bg-card px-2.5 py-1 text-xs">
              <FileCode2 className="size-3.5 text-primary" />
              <input
                value={pasteName}
                onChange={(e) => setPasteName(e.target.value)}
                className="w-32 bg-transparent font-medium outline-none placeholder:text-muted-foreground"
                placeholder="main.tf"
                spellCheck={false}
              />
            </div>
            <span className="ml-auto text-2xs text-muted-foreground">Extension sets the parser</span>
          </div>
          <div className="flex max-h-[420px] min-h-[300px]">
            <div
              aria-hidden
              className="scrollbar-thin shrink-0 select-none overflow-hidden bg-surface/60 px-3 py-3 text-right font-mono text-xs leading-relaxed text-muted-foreground/50"
            >
              {Array.from({ length: Math.max(16, pasteBody.split("\n").length) }).map((_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              value={pasteBody}
              onChange={(e) => setPasteBody(e.target.value)}
              spellCheck={false}
              placeholder="Paste Terraform HCL, Kubernetes YAML, or Terraform JSON here…"
              className="scrollbar-thin flex-1 resize-none bg-card p-3 font-mono text-xs leading-relaxed outline-none placeholder:text-muted-foreground/60"
            />
          </div>
        </div>
        <div className="mt-4">
          <Button
            variant="primary"
            disabled={!pasteBody.trim() || !pasteName.trim() || isPending}
            onClick={() => analyze.mutate({ text: { name: pasteName, body: pasteBody } })}
          >
            {isPending && <Spinner />}
            {isPending ? "Analyzing…" : "Run analysis"}
          </Button>
        </div>
      </TabsContent>

      {errMsg && (
        <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-danger/25 bg-danger/[0.07] px-3.5 py-3 text-sm text-danger animate-fade-in-up">
          <AlertCircle className="mt-0.5 size-4 shrink-0" />
          <span>{errMsg}</span>
        </div>
      )}
    </Tabs>
  );
}
