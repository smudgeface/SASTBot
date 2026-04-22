import { useParams, Link } from "react-router-dom";
import Editor from "@monaco-editor/react";
import { ArrowLeft, Download, Loader2 } from "lucide-react";

import { useSbomJson, useScanDetail } from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import { Button } from "@/components/ui/button";

function downloadBlob(text: string, filename: string) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SbomViewerPage() {
  const { id } = useParams<{ id: string }>();
  const scan = useScanDetail(id);
  const sbom = useSbomJson(id);
  const repos = useRepos();

  const repoName = repos.data?.find((r) => r.id === scan.data?.repo_id)?.name ?? "scan";
  const filename = `sbom-${repoName}-${(id ?? "").slice(0, 8)}.cdx.json`;

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2 border-b shrink-0">
        <div className="flex items-center gap-3">
          <Link
            to={`/scans/${id}`}
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {repoName}
          </Link>
          <span className="text-muted-foreground">/</span>
          <span className="text-sm font-medium">SBOM</span>
          <span className="text-xs text-muted-foreground font-mono">{filename}</span>
        </div>

        <Button
          variant="outline"
          size="sm"
          className="gap-1.5"
          disabled={!sbom.data}
          onClick={() => sbom.data && downloadBlob(sbom.data, filename)}
        >
          <Download className="h-4 w-4" />
          Download
        </Button>
      </div>

      {/* Editor area */}
      <div className="flex-1 min-h-0">
        {sbom.isLoading || scan.isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading SBOM…
          </div>
        ) : sbom.isError ? (
          <div className="flex items-center justify-center h-full text-sm text-destructive">
            Failed to load SBOM.
          </div>
        ) : (
          <Editor
            height="100%"
            language="json"
            value={sbom.data}
            theme="vs-dark"
            options={{
              readOnly: true,
              minimap: { enabled: true },
              lineNumbers: "on",
              folding: true,
              foldingStrategy: "indentation",
              wordWrap: "off",
              scrollBeyondLastLine: false,
              fontSize: 13,
              tabSize: 2,
              renderLineHighlight: "line",
              scrollbar: {
                verticalScrollbarSize: 10,
                horizontalScrollbarSize: 10,
              },
            }}
          />
        )}
      </div>
    </div>
  );
}
