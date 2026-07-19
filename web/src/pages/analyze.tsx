import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { UploadCloud, FileCode2, X, ClipboardType } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Spinner } from "@/components/ui/states";
import { cn } from "@/lib/utils";

const ACCEPT = ".yaml,.yml,.tf,.json,.hcl,.tgz";
const ACCEPT_LABEL = "YAML · TF · JSON · HCL · TGZ";

export function AnalyzePage() {
  const navigate = useNavigate();
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [pasteName, setPasteName] = useState("main.tf");
  const [pasteBody, setPasteBody] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const analyze = useMutation({
    mutationFn: (payload: { files?: File[]; text?: { name: string; body: string } }) =>
      payload.files
        ? api.analyzeFiles(payload.files)
        : api.analyzeText({ [payload.text!.name]: payload.text!.body }),
    onSuccess: (report) => navigate(`/reports/${report.report_id}`),
  });

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
    analyze.error instanceof ApiError
      ? analyze.error.message
      : analyze.error
        ? "Analysis failed. Is the API running?"
        : null;

  return (
    <div>
      <PageHeader
        title="Analyze infrastructure"
        description="Upload Terraform, Kubernetes, or Helm files — or paste content — to run a multi-agent governance review."
      />

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
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-12 text-center transition-colors",
              dragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/40"
            )}
          >
            <UploadCloud className="size-6 text-muted-foreground" />
            <p className="text-sm font-medium">Drop files here, or click to browse</p>
            <p className="text-xs text-muted-foreground">{ACCEPT_LABEL}</p>
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
            <div className="mt-4 flex flex-wrap gap-2">
              {files.map((f) => (
                <span
                  key={f.name}
                  className="inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-2.5 py-1 text-xs"
                >
                  <FileCode2 className="size-3.5 text-muted-foreground" />
                  {f.name}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFiles((prev) => prev.filter((x) => x.name !== f.name));
                    }}
                    className="text-muted-foreground hover:text-foreground"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="size-3.5" />
                  </button>
                </span>
              ))}
            </div>
          )}

          <div className="mt-6 flex items-center gap-3">
            <Button
              variant="primary"
              disabled={files.length === 0 || analyze.isPending}
              onClick={() => analyze.mutate({ files })}
            >
              {analyze.isPending && <Spinner />}
              {analyze.isPending ? "Analyzing…" : "Run analysis"}
            </Button>
            {files.length > 0 && (
              <Button variant="ghost" onClick={() => setFiles([])} disabled={analyze.isPending}>
                Clear
              </Button>
            )}
          </div>
        </TabsContent>

        <TabsContent value="paste">
          <Card>
            <CardContent className="space-y-3 pt-4">
              <div className="flex items-center gap-2">
                <label className="text-xs font-medium text-muted-foreground">Filename</label>
                <input
                  value={pasteName}
                  onChange={(e) => setPasteName(e.target.value)}
                  className="h-8 w-48 rounded-md border border-input bg-background px-2.5 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  placeholder="main.tf"
                />
                <Badge tone="neutral">Extension sets the parser</Badge>
              </div>
              <textarea
                value={pasteBody}
                onChange={(e) => setPasteBody(e.target.value)}
                rows={14}
                spellCheck={false}
                placeholder="Paste Terraform HCL, Kubernetes YAML, or Terraform JSON here…"
                className="scrollbar-thin w-full rounded-md border border-input bg-background p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
            </CardContent>
          </Card>
          <div className="mt-4">
            <Button
              variant="primary"
              disabled={!pasteBody.trim() || !pasteName.trim() || analyze.isPending}
              onClick={() => analyze.mutate({ text: { name: pasteName, body: pasteBody } })}
            >
              {analyze.isPending && <Spinner />}
              {analyze.isPending ? "Analyzing…" : "Run analysis"}
            </Button>
          </div>
        </TabsContent>
      </Tabs>

      {errMsg && (
        <div className="mt-4 rounded-md border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
          {errMsg}
        </div>
      )}
    </div>
  );
}
