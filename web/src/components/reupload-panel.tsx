import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileCode2, CheckCircle2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const ACCEPT = ".yaml,.yml,.tf,.json,.hcl,.tgz";

// Inline re-upload for reports loaded from history (which don't carry their
// original file contents). Lists the files the report needs, accepts a drop,
// reads them in-browser, and hands the contents up so the report's Generate-fix
// buttons activate — no need to leave and re-run a fresh analysis.
//
// Note: .tgz charts are rendered server-side at analysis time, so their text
// can't be reconstructed here; those still require a fresh analysis.
export function ReuploadPanel({
  neededFiles,
  provided,
  onFiles,
}: {
  neededFiles: string[];
  provided: Record<string, string>;
  onFiles: (contents: Record<string, string>) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const ingest = useCallback(
    async (files: FileList | File[]) => {
      const entries = await Promise.all(
        Array.from(files).map(
          (f) =>
            new Promise<[string, string]>((resolve) => {
              const reader = new FileReader();
              reader.onload = () => resolve([f.name, String(reader.result ?? "")]);
              reader.readAsText(f);
            })
        )
      );
      onFiles(Object.fromEntries(entries));
    },
    [onFiles]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer.files?.length) void ingest(e.dataTransfer.files);
    },
    [ingest]
  );

  const stillMissing = neededFiles.filter((f) => !(f in provided));
  const allProvided = stillMissing.length === 0 && neededFiles.length > 0;

  return (
    <div
      className={cn(
        "surface-raised rounded-lg border p-4",
        allProvided ? "border-success/30 bg-success/[0.04]" : "border-warning/30 bg-warning/[0.04]"
      )}
    >
      <div className="mb-3 flex items-start gap-2.5">
        {allProvided ? (
          <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" />
        ) : (
          <UploadCloud className="mt-0.5 size-4 shrink-0 text-warning" />
        )}
        <div>
          <h3 className="text-sm font-semibold">
            {allProvided
              ? "Files loaded — remediation is active"
              : "Re-upload original files for remediation"}
          </h3>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Reports opened from history don't include the original file contents (not persisted
            server-side by design). Re-upload them here so the Generate-fix buttons work — the
            files stay in your browser and aren't sent anywhere until you request a fix.
          </p>
        </div>
      </div>

      {/* Files the report needs, with per-file status */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {neededFiles.map((f) => {
          const have = f in provided;
          return (
            <span
              key={f}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-2xs",
                have
                  ? "border-success/25 bg-success/10 text-success"
                  : "border-border bg-surface text-muted-foreground"
              )}
            >
              {have ? <CheckCircle2 className="size-3" /> : <FileCode2 className="size-3" />}
              {f}
            </span>
          );
        })}
      </div>

      {!allProvided && (
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
            "flex cursor-pointer items-center justify-between gap-4 rounded-md border border-dashed px-4 py-3 transition-colors",
            dragging ? "border-primary bg-primary/[0.04]" : "border-border-strong hover:border-primary/40"
          )}
        >
          <div className="flex items-center gap-3">
            <UploadCloud className="size-5 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium">Drag and drop files here</p>
              <p className="text-2xs text-muted-foreground">YAML · YML · TF · JSON · HCL · TGZ</p>
            </div>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              inputRef.current?.click();
            }}
          >
            Browse files
          </Button>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ACCEPT}
            className="hidden"
            onChange={(e) => e.target.files && void ingest(e.target.files)}
          />
        </div>
      )}

      {allProvided && (
        <button
          onClick={() => onFiles({})}
          className="inline-flex items-center gap-1 text-2xs text-muted-foreground hover:text-foreground"
        >
          <X className="size-3" /> Clear uploaded files
        </button>
      )}
    </div>
  );
}
