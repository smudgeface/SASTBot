import { useParams, Link } from "react-router-dom";
import Editor from "@monaco-editor/react";
import { ArrowLeft, Download, Loader2 } from "lucide-react";

import { useScopeDetail, useScopeSbomJson } from "@/api/queries/scopes";
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

/**
 * Mirrors SbomViewerPage but reads from the scope-level SBOM endpoint
 * (latest successful scan for the scope). M6q feedback item #6.
 */
export default function ScopeSbomViewerPage() {
  const { id } = useParams<{ id: string }>();
  const scope = useScopeDetail(id);
  const sbom = useScopeSbomJson(id);

  const repoName = scope.data?.repo_name ?? "scope";
  const scopeSlug = (scope.data?.path ?? "/").replace(/^\/+/, "").replace(/\//g, "-") || "root";
  const filename = `sbom-${repoName}-${scopeSlug}.cdx.json`;

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <div className="flex items-center justify-between px-4 py-2 border-b shrink-0">
        <div className="flex items-center gap-3">
          <Link
            to={`/scopes/${id}`}
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {repoName}
            {scope.data?.path && scope.data.path !== "/" && (
              <span className="font-mono"> · {scope.data.path}</span>
            )}
          </Link>
          <span className="text-muted-foreground">/</span>
          <span className="text-sm font-medium">SBOM</span>
          <span className="text-[10px] text-muted-foreground" title="Curated CycloneDX 1.7 SBOM — post-Stage-2 LLM augmentation, matches the Components tab. This is the artifact to share for CRA compliance.">
            curated · CRA-ready
          </span>
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

      <div className="flex-1 min-h-0">
        {sbom.isLoading || scope.isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading SBOM…
          </div>
        ) : sbom.isError ? (
          <div className="flex items-center justify-center h-full text-sm text-destructive">
            Failed to load SBOM. No successful scan for this scope yet?
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
