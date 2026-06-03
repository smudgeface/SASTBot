import { useMemo, useState } from "react";
import {
  Eraser,
  Loader2,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  Trash2,
  Wifi,
} from "lucide-react";

import { useCredentials } from "@/api/queries/credentials";
import {
  useCheckRepoConnection,
  useCreateRepo,
  useDeleteRepo,
  usePurgeRepoCache,
  useRepos,
  useUpdateRepo,
} from "@/api/queries/repos";
import { useTriggerScan } from "@/api/queries/scans";
import type { AnalysisType, LlmEffort, Repo, RepoProtocol, RepoUpsertInput } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  CredentialFormFields,
  buildCredentialCreate,
  emptyCredentialForm,
  type CredentialFormState,
} from "@/components/CredentialFormFields";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { formatDate } from "@/lib/format";

/** Credential kinds that can authenticate a git clone. */
const REPO_CRED_KINDS = ["https_token", "https_basic", "ssh_key"] as const;

const REPOS_PAGE_SIZE = 100;

function Pager({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 px-1">
      <span>
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          ‹
        </Button>
        <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
          ›
        </Button>
      </div>
    </div>
  );
}

export default function ReposPage() {
  const [page, setPage] = useState(1);
  const repos = useRepos({ page, page_size: REPOS_PAGE_SIZE });
  const deleteRepo = useDeleteRepo();
  const triggerScan = useTriggerScan();
  const purgeCache = usePurgeRepoCache();
  const checkConnection = useCheckRepoConnection();
  const { toast } = useToast();
  const [checkingId, setCheckingId] = useState<string | null>(null);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Repo | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Repo | null>(null);
  const [pendingPurge, setPendingPurge] = useState<Repo | null>(null);

  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };

  const openEdit = (repo: Repo) => {
    setEditing(repo);
    setFormOpen(true);
  };

  const onScanNow = async (repo: Repo) => {
    try {
      await triggerScan.mutateAsync(repo.id);
      toast({ title: "Scan queued", description: repo.name });
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to queue scan",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const onCheckConnection = async (repo: Repo) => {
    setCheckingId(repo.id);
    try {
      const result = await checkConnection.mutateAsync(repo.id);
      if (result.ok) {
        const branchList = result.branches.length > 0
          ? result.branches.slice(0, 5).join(", ") + (result.branches.length > 5 ? ` +${result.branches.length - 5} more` : "")
          : "no branches found";
        toast({
          title: `✓ Connected — ${repo.name}`,
          description: `Branches: ${branchList}`,
        });
      } else {
        toast({
          variant: "destructive",
          title: `Connection failed — ${repo.name}`,
          description: result.error,
        });
      }
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Check failed",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setCheckingId(null);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteRepo.mutateAsync(pendingDelete.id);
      toast({ title: "Repository removed", description: pendingDelete.name });
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to delete repository",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setPendingDelete(null);
    }
  };

  const confirmPurge = async () => {
    if (!pendingPurge) return;
    try {
      await purgeCache.mutateAsync(pendingPurge.id);
      toast({ title: "Cache purged", description: pendingPurge.name });
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to purge cache",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setPendingPurge(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Repositories</h1>
          <p className="text-sm text-muted-foreground">
            Source repositories registered for scanning.
          </p>
        </div>
        <Button onClick={openCreate} className="gap-2">
          <Plus className="h-4 w-4" /> Add repository
        </Button>
      </div>

      {repos.isError ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            Failed to load repositories.
          </CardContent>
        </Card>
      ) : null}

      {!repos.isLoading && (repos.data?.total ?? 0) === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>No repositories yet</CardTitle>
            <CardDescription>Add one to start scanning.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={openCreate} className="gap-2">
              <Plus className="h-4 w-4" /> Add your first repository
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {(repos.data?.total ?? 0) > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Branch</TableHead>
                <TableHead>Analysis</TableHead>
                <TableHead>Cache</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {repos.data?.items.map((repo) => (
                <TableRow key={repo.id}>
                  <TableCell className="font-medium">{repo.name}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {repo.url}
                  </TableCell>
                  <TableCell className="uppercase">{repo.protocol}</TableCell>
                  <TableCell>{repo.default_branch}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {repo.analysis_types.map((t) => (
                        <Badge key={t} variant="secondary" className="uppercase">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <CacheCell repo={repo} />
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label="Repository actions">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onSelect={() => onCheckConnection(repo)}
                          disabled={checkingId === repo.id}
                        >
                          {checkingId === repo.id
                            ? <Loader2 className="h-4 w-4 animate-spin" />
                            : <Wifi className="h-4 w-4" />}
                          Check access
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => onScanNow(repo)}>
                          <Play className="h-4 w-4" /> Scan now
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => openEdit(repo)}>
                          <Pencil className="h-4 w-4" /> Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onSelect={() => setPendingPurge(repo)}
                          disabled={!repo.clone_present}
                        >
                          <Eraser className="h-4 w-4" /> Purge cache
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onSelect={() => setPendingDelete(repo)}
                          className="text-destructive focus:text-destructive"
                        >
                          <Trash2 className="h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {repos.data && (
            <div className="px-4 pb-4">
              <Pager page={page} pageSize={REPOS_PAGE_SIZE} total={repos.data.total} onPage={setPage} />
            </div>
          )}
        </Card>
      ) : null}

      <RepoFormDialog
        key={editing?.id ?? "new"}
        open={formOpen}
        onOpenChange={setFormOpen}
        repo={editing}
      />

      <Dialog open={!!pendingDelete} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete repository?</DialogTitle>
            <DialogDescription>
              {pendingDelete ? `"${pendingDelete.name}" will be removed permanently.` : null}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingDelete(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
              disabled={deleteRepo.isPending}
            >
              {deleteRepo.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!pendingPurge} onOpenChange={(open) => !open && setPendingPurge(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Purge cached clone?</DialogTitle>
            <DialogDescription>
              {pendingPurge ? (
                <>
                  The on-disk clone for "{pendingPurge.name}" will be removed. The next
                  scan will start from a fresh clone.
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingPurge(null)}>
              Cancel
            </Button>
            <Button onClick={confirmPurge} disabled={purgeCache.isPending}>
              {purgeCache.isPending ? "Purging…" : "Purge"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CacheCell({ repo }: { repo: Repo }) {
  if (!repo.retain_clone) {
    return <span className="text-xs text-muted-foreground italic">ephemeral</span>;
  }
  // `clone_present` is live disk truth — not `last_cloned_at` (a persisted
  // timestamp that survives a DB restore even though the clone volume doesn't).
  if (!repo.clone_present) {
    return <span className="text-xs text-muted-foreground">retain (empty)</span>;
  }
  return (
    <div className="text-xs">
      <Badge variant="secondary" className="uppercase">
        cached
      </Badge>
      {repo.last_cloned_at && (
        <div className="text-muted-foreground mt-1">{formatDate(repo.last_cloned_at)}</div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------
// Repo form dialog
// --------------------------------------------------------------------------

interface RepoFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  repo: Repo | null;
}

type CredentialChoice = "existing" | "new";

function RepoFormDialog({ open, onOpenChange, repo }: RepoFormDialogProps) {
  const credentials = useCredentials();
  const createRepo = useCreateRepo();
  const updateRepo = useUpdateRepo(repo?.id ?? "");
  const { toast } = useToast();

  const [name, setName] = useState(repo?.name ?? "");
  const [url, setUrl] = useState(repo?.url ?? "");
  const [protocol, setProtocol] = useState<RepoProtocol>(repo?.protocol ?? "https");
  const [defaultBranch, setDefaultBranch] = useState(repo?.default_branch ?? "main");
  const [scanPathsText, setScanPathsText] = useState(
    (repo?.scan_paths ?? []).join(", "),
  );
  const [ignorePathsText, setIgnorePathsText] = useState(
    (repo?.ignore_paths ?? []).join(", "),
  );
  const [sca, setSca] = useState<boolean>(repo?.analysis_types.includes("sca") ?? true);
  const [sast, setSast] = useState<boolean>(repo?.analysis_types.includes("sast") ?? true);
  const [retainClone, setRetainClone] = useState<boolean>(repo?.retain_clone ?? false);
  const [reachabilityEnabled, setReachabilityEnabled] = useState<boolean>(repo?.reachability_enabled ?? true);
  const [includeDevDeps, setIncludeDevDeps] = useState<boolean>(repo?.include_dev_deps ?? false);
  const [llmSastEffort, setLlmSastEffort] = useState<LlmEffort>(repo?.llm_sast_effort ?? "xhigh");
  const [llmRecheckEffort, setLlmRecheckEffort] = useState<LlmEffort>(repo?.llm_recheck_effort ?? "medium");
  const [llmSbomEffort, setLlmSbomEffort] = useState<LlmEffort>(repo?.llm_sbom_effort ?? "medium");
  // Token budgets: empty string = null (use default). Stored as strings for input binding.
  const [llmSbomTokenBudget, setLlmSbomTokenBudget] = useState<string>(
    repo?.llm_sbom_token_budget != null ? String(repo.llm_sbom_token_budget) : "",
  );
  const [llmSbomRecheckTokenBudget, setLlmSbomRecheckTokenBudget] = useState<string>(
    repo?.llm_sbom_recheck_token_budget != null ? String(repo.llm_sbom_recheck_token_budget) : "",
  );
  const [llmSastTokenBudget, setLlmSastTokenBudget] = useState<string>(
    repo?.llm_sast_token_budget != null ? String(repo.llm_sast_token_budget) : "",
  );
  const [llmRecheckTokenBudget, setLlmRecheckTokenBudget] = useState<string>(
    repo?.llm_recheck_token_budget != null ? String(repo.llm_recheck_token_budget) : "",
  );
  const [firstPartyNamespacesText, setFirstPartyNamespacesText] = useState<string>(
    (repo?.first_party_namespaces ?? []).join(", "),
  );
  const [vendoredDirsText, setVendoredDirsText] = useState<string>(
    (repo?.vendored_dirs ?? ["extern/", "third-party/", "vendor/"]).join(", "),
  );
  const [sourceUrlTemplate, setSourceUrlTemplate] = useState<string>(repo?.source_url_template ?? "");

  const [credentialChoice, setCredentialChoice] = useState<CredentialChoice>(
    repo?.credential_id ? "existing" : "new",
  );
  const [credentialId, setCredentialId] = useState<string>(repo?.credential_id ?? "");
  const [credFormState, setCredFormState] = useState<CredentialFormState>(
    emptyCredentialForm("https_token"),
  );

  const busy = createRepo.isPending || updateRepo.isPending;

  const filteredCredentials = useMemo(
    () =>
      (credentials.data?.items ?? []).filter((c) =>
        (REPO_CRED_KINDS as readonly string[]).includes(c.kind),
      ),
    [credentials.data],
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const analysis_types: AnalysisType[] = [];
    if (sca) analysis_types.push("sca");
    if (sast) analysis_types.push("sast");

    const scan_paths = scanPathsText
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

    const ignore_paths = ignorePathsText
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

    const first_party_namespaces = firstPartyNamespacesText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const vendored_dirs = vendoredDirsText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    // Parse token budget inputs: empty → null (use default), positive int → override.
    const parseBudget = (s: string): number | null => {
      const n = parseInt(s.trim(), 10);
      return !isNaN(n) && n > 0 ? n : null;
    };

    const payload: RepoUpsertInput = {
      name: name.trim(),
      url: url.trim(),
      protocol,
      default_branch: defaultBranch.trim() || "main",
      scan_paths,
      ignore_paths,
      analysis_types,
      retain_clone: retainClone,
      reachability_enabled: reachabilityEnabled,
      include_dev_deps: includeDevDeps,
      llm_sast_effort: llmSastEffort,
      llm_recheck_effort: llmRecheckEffort,
      first_party_namespaces,
      vendored_dirs,
      llm_sbom_effort: llmSbomEffort,
      llm_sbom_token_budget: parseBudget(llmSbomTokenBudget),
      llm_sbom_recheck_token_budget: parseBudget(llmSbomRecheckTokenBudget),
      llm_sast_token_budget: parseBudget(llmSastTokenBudget),
      llm_recheck_token_budget: parseBudget(llmRecheckTokenBudget),
      source_url_template: sourceUrlTemplate.trim() || null,
    };

    if (credentialChoice === "existing") {
      payload.credential_id = credentialId || null;
    } else {
      // Only try to build an inline credential if the user typed anything.
      const hasAnyField =
        credFormState.name.trim() ||
        credFormState.value ||
        credFormState.username.trim() ||
        credFormState.password ||
        credFormState.private_key.trim();
      if (hasAnyField) {
        const built = buildCredentialCreate(credFormState);
        if (!built.ok) {
          toast({ variant: "destructive", title: built.error });
          return;
        }
        payload.credential = built.input;
      } else {
        payload.credential_id = null;
      }
    }

    try {
      if (repo) {
        await updateRepo.mutateAsync(payload);
        toast({ title: "Repository updated", description: payload.name });
      } else {
        await createRepo.mutateAsync(payload);
        toast({ title: "Repository added", description: payload.name });
      }
      onOpenChange(false);
      if (!repo) {
        setName("");
        setUrl("");
        setProtocol("https");
        setDefaultBranch("main");
        setScanPathsText("");
        setIgnorePathsText("");
        setSca(true);
        setSast(true);
        setRetainClone(false);
        setCredentialChoice("new");
        setCredentialId("");
        setCredFormState(emptyCredentialForm("https_token"));
      }
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to save repository",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{repo ? "Edit repository" : "Add repository"}</DialogTitle>
          <DialogDescription>
            {repo ? "Update the repository configuration." : "Register a new source repository."}
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-4 max-h-[70vh] overflow-y-auto pr-1" onSubmit={handleSubmit}>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="repo-name">Name</Label>
              <Input
                id="repo-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
              <p className="text-xs text-muted-foreground">
                Display name shown in scopes, dashboards, and Jira tickets.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="repo-branch">Branch</Label>
              <Input
                id="repo-branch"
                value={defaultBranch}
                onChange={(e) => setDefaultBranch(e.target.value)}
                placeholder="main"
              />
              <p className="text-xs text-muted-foreground">
                The branch SASTBot scans on every run.
              </p>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="repo-url">Clone URL</Label>
            <Input
              id="repo-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="git@github.com:org/repo.git"
              required
            />
            <p className="text-xs text-muted-foreground">
              The HTTPS or SSH URL used to clone the repo. Match the protocol selected below.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label>Protocol</Label>
            <div className="flex gap-4 text-sm">
              <label className="inline-flex items-center gap-2">
                <input
                  type="radio"
                  name="protocol"
                  value="https"
                  checked={protocol === "https"}
                  onChange={() => setProtocol("https")}
                />
                HTTPS
              </label>
              <label className="inline-flex items-center gap-2">
                <input
                  type="radio"
                  name="protocol"
                  value="ssh"
                  checked={protocol === "ssh"}
                  onChange={() => setProtocol("ssh")}
                />
                SSH
              </label>
            </div>
            <p className="text-xs text-muted-foreground">
              Matches the URL above. HTTPS uses a token credential; SSH uses a private-key credential.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="repo-paths">Scan paths</Label>
            <Input
              id="repo-paths"
              value={scanPathsText}
              onChange={(e) => setScanPathsText(e.target.value)}
              placeholder="/, services/api"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated paths, relative to the repo root. Each path becomes its own scope —
              issues are tracked, triaged, and reported per scope. Use <code className="font-mono">/</code> to scan
              the entire repo. When paths overlap (e.g. <code className="font-mono">/</code> and <code className="font-mono">/services/api</code>),
              the deeper path owns its tree and is skipped by the broader scope.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="repo-ignore-paths">Ignore paths</Label>
            <Input
              id="repo-ignore-paths"
              value={ignorePathsText}
              onChange={(e) => setIgnorePathsText(e.target.value)}
              placeholder="scripts/internal, tools/dev"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated paths to skip from every scan. Useful for internal-only scripts,
              vendored code, or generated output that doesn't ship to production.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label>Analysis</Label>
            <div className="flex flex-wrap gap-4 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={sca} onChange={(e) => setSca(e.target.checked)} />
                SCA (dependencies)
              </label>
              <label className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={sast}
                  onChange={(e) => setSast(e.target.checked)}
                />
                SAST (source code)
              </label>
            </div>
            <p className="text-xs text-muted-foreground">
              SCA queries OSV for known vulnerabilities in your dependencies. SAST runs a
              Claude-driven agent over the source to detect dangerous patterns (XXE, command
              injection, hardcoded secrets, etc.) and identify vendored libraries cdxgen can't
              see. Pick at least one.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label>Clone cache</Label>
            <label className="inline-flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={retainClone}
                onChange={(e) => setRetainClone(e.target.checked)}
              />
              <div>
                Retain the clone between scans
                <p className="text-xs text-muted-foreground">
                  Trades disk space for scan speed — subsequent scans do a `git fetch` instead
                  of re-cloning. Purge from the row menu to recover the space or force a clean run.
                </p>
              </div>
            </label>
          </div>

          <div className="space-y-1.5">
            <Label>Reachability analysis</Label>
            <label className="inline-flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={reachabilityEnabled}
                onChange={(e) => setReachabilityEnabled(e.target.checked)}
              />
              <div>
                Assess whether high+critical SCA findings are actually reachable
                <p className="text-xs text-muted-foreground">
                  Adds time and LLM token cost. Disable if you want SAST + SCA scans without
                  the call-site reachability check.
                </p>
              </div>
            </label>
          </div>

          <div className="space-y-1.5">
            <Label>Dependency scope</Label>
            <label className="inline-flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={includeDevDeps}
                onChange={(e) => setIncludeDevDeps(e.target.checked)}
              />
              <div>
                Include npm dev-only dependencies
                <p className="text-xs text-muted-foreground">
                  Off by default. When off, components cdxgen 12.2+ flags as dev-only
                  (npm-lockfile <code>dev: true</code>) are excluded from vulnerability
                  scanning, the SCA reachability hints, the Components/SCA default views,
                  AND the curated SBOM. Turn on only for repos where dev/test/build
                  dependencies are in scope for your compliance artifact. npm-only signal
                  — non-npm components are always included. (Caveat: cdxgen issue #3927 —{" "}
                  <code>devOptional</code> lockfile entries miss the marker and still slip
                  through.)
                </p>
              </div>
            </label>
          </div>

          <div className="space-y-1.5">
            <Label>LLM effort</Label>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor="llm-sast-effort" className="text-xs text-muted-foreground">
                  SAST detection
                </Label>
                <select
                  id="llm-sast-effort"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  value={llmSastEffort}
                  onChange={(e) => setLlmSastEffort(e.target.value as LlmEffort)}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="xhigh">xhigh (Opus only)</option>
                  <option value="max">max</option>
                </select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="llm-recheck-effort" className="text-xs text-muted-foreground">
                  SAST recheck
                </Label>
                <select
                  id="llm-recheck-effort"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  value={llmRecheckEffort}
                  onChange={(e) => setLlmRecheckEffort(e.target.value as LlmEffort)}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="xhigh">xhigh (Opus only)</option>
                  <option value="max">max</option>
                </select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="llm-sbom-effort" className="text-xs text-muted-foreground">
                  SBOM augmentation
                </Label>
                <select
                  id="llm-sbom-effort"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  value={llmSbomEffort}
                  onChange={(e) => setLlmSbomEffort(e.target.value as LlmEffort)}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="xhigh">xhigh (Opus only)</option>
                  <option value="max">max</option>
                </select>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Passed to <code className="font-mono">claude -p --effort</code>. Detection is
              open-ended search and benefits from <code>xhigh</code> on Opus 4.7; recheck and
              SBOM augmentation are classification/verification work and are fine at{" "}
              <code>medium</code>. <code>xhigh</code> is Opus-only — Sonnet silently degrades it.
            </p>
          </div>

          <details className="space-y-1.5">
            <summary className="cursor-pointer text-sm font-medium select-none">
              Token budgets{" "}
              <span className="text-xs text-muted-foreground font-normal">
                (optional — leave blank to use defaults)
              </span>
            </summary>
            <div className="mt-2 grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="llm-sbom-token-budget" className="text-xs text-muted-foreground">
                  SBOM augmentation (default 200 000)
                </Label>
                <Input
                  id="llm-sbom-token-budget"
                  type="number"
                  min={1}
                  step={1}
                  value={llmSbomTokenBudget}
                  onChange={(e) => setLlmSbomTokenBudget(e.target.value)}
                  placeholder="200000"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="llm-sbom-recheck-token-budget" className="text-xs text-muted-foreground">
                  SBOM recheck (default 50 000)
                </Label>
                <Input
                  id="llm-sbom-recheck-token-budget"
                  type="number"
                  min={1}
                  step={1}
                  value={llmSbomRecheckTokenBudget}
                  onChange={(e) => setLlmSbomRecheckTokenBudget(e.target.value)}
                  placeholder="50000"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="llm-sast-token-budget" className="text-xs text-muted-foreground">
                  SAST detection (default 300 000)
                </Label>
                <Input
                  id="llm-sast-token-budget"
                  type="number"
                  min={1}
                  step={1}
                  value={llmSastTokenBudget}
                  onChange={(e) => setLlmSastTokenBudget(e.target.value)}
                  placeholder="300000"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="llm-recheck-token-budget" className="text-xs text-muted-foreground">
                  SAST recheck (default 50 000)
                </Label>
                <Input
                  id="llm-recheck-token-budget"
                  type="number"
                  min={1}
                  step={1}
                  value={llmRecheckTokenBudget}
                  onChange={(e) => setLlmRecheckTokenBudget(e.target.value)}
                  placeholder="50000"
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Maximum tokens the LLM may consume per phase per scan. Empty = use the system
              default. Raise for very large repos; lower to cap cost on simple ones. The
              live-progress bar in the scopes list reflects these caps.
            </p>
          </details>

          <div className="space-y-1.5">
            <Label htmlFor="first-party-namespaces">First-party namespaces</Label>
            <Input
              id="first-party-namespaces"
              value={firstPartyNamespacesText}
              onChange={(e) => setFirstPartyNamespacesText(e.target.value)}
              placeholder="GoSdkNet, kApiNet, LMI, MyOrg"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated name prefixes the LLM SBOM augmentation pass treats as first-party
              code and drops from the SBOM. Case-insensitive prefix match. Leave blank if all
              packages are third-party.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="vendored-dirs">Vendored directories</Label>
            <Input
              id="vendored-dirs"
              value={vendoredDirsText}
              onChange={(e) => setVendoredDirsText(e.target.value)}
              placeholder="extern/, third-party/, vendor/"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated directories the LLM inspects for vendored third-party libraries that
              cdxgen missed. Defaults to <code>extern/, third-party/, vendor/</code>. Paths are
              relative to the scope root.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="source-url-template">Source URL template</Label>
            <Input
              id="source-url-template"
              value={sourceUrlTemplate}
              onChange={(e) => setSourceUrlTemplate(e.target.value)}
              placeholder="https://git.example.com/repos/owner/repo/browse/$FILE#$LINE"
            />
            <p className="text-xs text-muted-foreground">
              Optional. Used to make file paths in SAST/SCA detail views clickable.
              Supports <code className="font-mono">$FILE</code> (repo-relative path) and{" "}
              <code className="font-mono">$LINE</code> (line number) placeholders.
            </p>
          </div>

          <Separator />

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-semibold">Credential</Label>
              <div className="flex gap-3 text-xs">
                <label className="inline-flex items-center gap-1.5">
                  <input
                    type="radio"
                    name="credential-choice"
                    value="existing"
                    checked={credentialChoice === "existing"}
                    onChange={() => setCredentialChoice("existing")}
                  />
                  Use existing
                </label>
                <label className="inline-flex items-center gap-1.5">
                  <input
                    type="radio"
                    name="credential-choice"
                    value="new"
                    checked={credentialChoice === "new"}
                    onChange={() => setCredentialChoice("new")}
                  />
                  Create new
                </label>
              </div>
            </div>

            {credentialChoice === "existing" ? (
              // Same Radix quirk-pair as SettingsPage credential picker; see
              // the long comment there for the full explanation. Short
              // version: render the label explicitly via SelectValue
              // children to skip Radix's deferred item registration, AND
              // reject onValueChange("") when no options are mounted so the
              // value isn't silently cleared by Radix's mismatch handler
              // while credentials are still loading.
              (() => {
                const selected = filteredCredentials.find((c) => c.id === credentialId);
                const handleValueChange = (v: string) => {
                  if (v === "" && filteredCredentials.length === 0) return;
                  setCredentialId(v);
                };
                return (
                  <Select
                    value={credentialId}
                    onValueChange={handleValueChange}
                    disabled={credentials.isLoading}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select a credential">
                        {credentials.isLoading ? (
                          "Loading credentials…"
                        ) : selected ? (
                          <>
                            {selected.name} — <span className="text-muted-foreground">{selected.kind}</span>
                          </>
                        ) : null}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      {filteredCredentials.length === 0 ? (
                        <div className="px-3 py-2 text-xs text-muted-foreground">
                          No compatible credentials yet. Create one instead.
                        </div>
                      ) : null}
                      {filteredCredentials.map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          {c.name} — <span className="text-muted-foreground">{c.kind}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                );
              })()
            ) : (
              <CredentialFormFields
                idPrefix="repo-cred"
                state={credFormState}
                onChange={setCredFormState}
                allowedKinds={REPO_CRED_KINDS}
              />
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? "Saving…" : repo ? "Save changes" : "Add repository"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
