import { useMemo, useState } from "react";
import {
  CheckCircle2,
  Eraser,
  Loader2,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  Trash2,
  Wifi,
  XCircle,
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
import type { AnalysisType, Repo, RepoProtocol, RepoUpsertInput, SastEngine } from "@/api/types";
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

export default function ReposPage() {
  const repos = useRepos();
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

      {!repos.isLoading && (repos.data?.length ?? 0) === 0 ? (
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

      {(repos.data?.length ?? 0) > 0 ? (
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
              {repos.data?.map((repo) => (
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
                          disabled={!repo.last_cloned_at}
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
  if (!repo.last_cloned_at) {
    return <span className="text-xs text-muted-foreground">retain (empty)</span>;
  }
  return (
    <div className="text-xs">
      <Badge variant="secondary" className="uppercase">
        cached
      </Badge>
      <div className="text-muted-foreground mt-1">{formatDate(repo.last_cloned_at)}</div>
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
  const [sastEngine, setSastEngine] = useState<SastEngine>(repo?.sast_engine ?? "opengrep");
  const [reachabilityEnabled, setReachabilityEnabled] = useState<boolean>(repo?.reachability_enabled ?? true);
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
      (credentials.data ?? []).filter((c) =>
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

    const payload: RepoUpsertInput = {
      name: name.trim(),
      url: url.trim(),
      protocol,
      default_branch: defaultBranch.trim() || "main",
      scan_paths,
      ignore_paths,
      analysis_types,
      retain_clone: retainClone,
      sast_engine: sastEngine,
      reachability_enabled: reachabilityEnabled,
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
              SCA queries OSV for known vulnerabilities in your dependencies. SAST runs Opengrep
              against the source for dangerous patterns (XXE, command injection, hardcoded
              secrets, etc.). Pick at least one.
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
            <Label htmlFor="sast-engine">SAST engine</Label>
            <select
              id="sast-engine"
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm"
              value={sastEngine}
              onChange={(e) => setSastEngine(e.target.value as SastEngine)}
            >
              <option value="opengrep">Opengrep + LLM triage (legacy)</option>
              <option value="llm">Claude Code CLI (LLM-mode)</option>
            </select>
            <p className="text-xs text-muted-foreground">
              <strong>Opengrep</strong>: rule-based static analyzer; LLM triages each finding.
              {" "}<strong>LLM-mode</strong>: a single Claude Code CLI agentic pass replaces Opengrep,
              also identifies vendored libraries and reachable SCA call sites in one go.
              LLM-mode requires the LLM endpoint in Settings to be configured.
            </p>
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
              <Select value={credentialId} onValueChange={setCredentialId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a credential" />
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
