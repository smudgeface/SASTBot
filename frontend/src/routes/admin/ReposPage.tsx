import { useMemo, useState } from "react";
import { MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react";

import { useCredentials } from "@/api/queries/credentials";
import { useCreateRepo, useDeleteRepo, useRepos, useUpdateRepo } from "@/api/queries/repos";
import type { AnalysisType, Repo, RepoProtocol, RepoUpsertInput } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Input, Textarea } from "@/components/ui/input";
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

export default function ReposPage() {
  const repos = useRepos();
  const deleteRepo = useDeleteRepo();
  const { toast } = useToast();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Repo | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Repo | null>(null);

  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };

  const openEdit = (repo: Repo) => {
    setEditing(repo);
    setFormOpen(true);
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
                <TableHead>Default branch</TableHead>
                <TableHead>Analysis</TableHead>
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
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label="Repository actions">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => openEdit(repo)}>
                          <Pencil className="h-4 w-4" /> Edit
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
              {pendingDelete ? `“${pendingDelete.name}” will be removed permanently.` : null}
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
  const [sca, setSca] = useState<boolean>(repo?.analysis_types.includes("sca") ?? true);
  const [sast, setSast] = useState<boolean>(repo?.analysis_types.includes("sast") ?? true);

  const [credentialChoice, setCredentialChoice] = useState<CredentialChoice>(
    repo?.credential_id ? "existing" : "new",
  );
  const [credentialId, setCredentialId] = useState<string>(repo?.credential_id ?? "");
  const [newKind, setNewKind] = useState("https_token");
  const [newLabel, setNewLabel] = useState("");
  const [newValue, setNewValue] = useState("");

  const busy = createRepo.isPending || updateRepo.isPending;

  const filteredCredentials = useMemo(() => credentials.data ?? [], [credentials.data]);

  const reset = () => {
    setName("");
    setUrl("");
    setProtocol("https");
    setDefaultBranch("main");
    setScanPathsText("");
    setSca(true);
    setSast(true);
    setCredentialChoice("new");
    setCredentialId("");
    setNewKind("https_token");
    setNewLabel("");
    setNewValue("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const analysis_types: AnalysisType[] = [];
    if (sca) analysis_types.push("sca");
    if (sast) analysis_types.push("sast");

    const scan_paths = scanPathsText
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

    const payload: RepoUpsertInput = {
      name: name.trim(),
      url: url.trim(),
      protocol,
      default_branch: defaultBranch.trim() || "main",
      scan_paths,
      analysis_types,
    };

    if (credentialChoice === "existing") {
      payload.credential_id = credentialId || null;
    } else if (newLabel.trim() && newValue.trim()) {
      payload.credential = {
        kind: newKind,
        label: newLabel.trim(),
        value: newValue,
      };
    } else {
      payload.credential_id = null;
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
      if (!repo) reset();
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

        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="repo-name">Name</Label>
              <Input
                id="repo-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="repo-branch">Default branch</Label>
              <Input
                id="repo-branch"
                value={defaultBranch}
                onChange={(e) => setDefaultBranch(e.target.value)}
                placeholder="main"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="repo-url">URL</Label>
            <Input
              id="repo-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="git@github.com:org/repo.git"
              required
            />
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
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="repo-paths">Scan paths</Label>
            <Input
              id="repo-paths"
              value={scanPathsText}
              onChange={(e) => setScanPathsText(e.target.value)}
              placeholder="src, services/api"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated paths, relative to the repo root. Leave blank to scan everything.
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
                      No credentials yet. Create one instead.
                    </div>
                  ) : null}
                  {filteredCredentials.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.label} — <span className="text-muted-foreground">{c.kind}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="cred-kind">Kind</Label>
                  <Select value={newKind} onValueChange={setNewKind}>
                    <SelectTrigger id="cred-kind">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="https_token">HTTPS token</SelectItem>
                      <SelectItem value="https_basic">HTTPS basic auth</SelectItem>
                      <SelectItem value="ssh_key">SSH key</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="cred-label">Label</Label>
                  <Input
                    id="cred-label"
                    value={newLabel}
                    onChange={(e) => setNewLabel(e.target.value)}
                    placeholder="github-read-token"
                  />
                </div>
                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="cred-value">Value</Label>
                  <Textarea
                    id="cred-value"
                    value={newValue}
                    onChange={(e) => setNewValue(e.target.value)}
                    placeholder="Paste token or key. Encrypted at rest."
                    rows={3}
                  />
                </div>
              </div>
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
