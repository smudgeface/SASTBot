import { useState } from "react";
import { KeyRound, MoreHorizontal, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  useCreateCredential,
  useCredentials,
  useDeleteCredential,
  useRenameCredential,
  useRotateCredential,
} from "@/api/queries/credentials";
import type { Credential, CredentialReferences } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  CredentialFormFields,
  buildCredentialCreate,
  buildCredentialRotate,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { formatDate, truncate } from "@/lib/format";

export default function CredentialsPage() {
  const credentials = useCredentials();
  const [addOpen, setAddOpen] = useState(false);
  const [renameTarget, setRenameTarget] = useState<Credential | null>(null);
  const [rotateTarget, setRotateTarget] = useState<Credential | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Credential | null>(null);

  const items = credentials.data ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Credentials</h1>
          <p className="text-sm text-muted-foreground">
            Credential values are encrypted in the database and cannot be viewed after
            creation. To replace a value, use <em>Rotate</em>.
          </p>
        </div>
        <Button onClick={() => setAddOpen(true)} className="gap-2">
          <Plus className="h-4 w-4" /> Add credential
        </Button>
      </div>

      {!credentials.isLoading && items.length === 0 ? (
        <Card>
          <CardHeader className="flex flex-row items-center gap-3">
            <KeyRound className="h-5 w-5 text-muted-foreground" />
            <div>
              <CardTitle>No credentials yet</CardTitle>
              <CardDescription>
                Add one now, or create one inline when registering a repository.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <Button onClick={() => setAddOpen(true)} className="gap-2">
              <Plus className="h-4 w-4" /> Add your first credential
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {items.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Used by</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    <div className="font-medium">{c.name}</div>
                    {c.metadata?.username ? (
                      <div className="text-xs text-muted-foreground">
                        user: <span className="font-mono">{c.metadata.username}</span>
                      </div>
                    ) : null}
                    {c.metadata?.has_known_hosts ? (
                      <div className="text-xs text-muted-foreground">host-key pinned</div>
                    ) : null}
                    <div
                      className="text-xs text-muted-foreground font-mono mt-0.5"
                      title={c.id}
                    >
                      {truncate(c.id, 10)}
                    </div>
                  </TableCell>
                  <TableCell className="uppercase text-xs text-muted-foreground">
                    {c.kind}
                  </TableCell>
                  <TableCell>
                    <UsedByCell refs={c.references} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(c.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label="Credential actions">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => setRenameTarget(c)}>
                          <Pencil className="h-4 w-4" /> Rename
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => setRotateTarget(c)}>
                          <RefreshCw className="h-4 w-4" /> Rotate value
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onSelect={() => setDeleteTarget(c)}
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

      <AddCredentialDialog open={addOpen} onOpenChange={setAddOpen} />
      <RenameCredentialDialog
        target={renameTarget}
        onOpenChange={(open) => !open && setRenameTarget(null)}
      />
      <RotateCredentialDialog
        target={rotateTarget}
        onOpenChange={(open) => !open && setRotateTarget(null)}
      />
      <DeleteCredentialDialog
        target={deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-dialogs
// ---------------------------------------------------------------------------

function UsedByCell({ refs }: { refs: CredentialReferences }) {
  const bits: string[] = [];
  if (refs.repos.length > 0) bits.push(...refs.repos.map((r) => r.name));
  if (refs.jira_settings) bits.push("Jira settings");
  if (refs.llm_settings) bits.push("LLM settings");
  if (bits.length === 0) {
    return <span className="text-xs text-muted-foreground italic">unused</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {bits.map((b) => (
        <Badge key={b} variant="secondary" className="text-xs">
          {b}
        </Badge>
      ))}
    </div>
  );
}

function AddCredentialDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [state, setState] = useState<CredentialFormState>(emptyCredentialForm());
  const createCred = useCreateCredential();
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = buildCredentialCreate(state);
    if (!result.ok) {
      toast({ variant: "destructive", title: result.error });
      return;
    }
    try {
      await createCred.mutateAsync(result.input);
      toast({ title: "Credential created", description: state.name });
      setState(emptyCredentialForm());
      onOpenChange(false);
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to create credential",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Add credential</DialogTitle>
          <DialogDescription>
            Choose a kind, give it a name, and paste the secret. Values are encrypted at
            rest with AES-256-GCM.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <CredentialFormFields idPrefix="add-cred" state={state} onChange={setState} />
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setState(emptyCredentialForm());
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={createCred.isPending}>
              {createCred.isPending ? "Saving…" : "Add credential"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RenameCredentialDialog({
  target,
  onOpenChange,
}: {
  target: Credential | null;
  onOpenChange: (open: boolean) => void;
}) {
  const [name, setName] = useState("");
  const rename = useRenameCredential(target?.id ?? "");
  const { toast } = useToast();

  // Reset the input whenever the dialog target changes.
  const currentName = target?.name ?? "";
  if (target && name === "" && currentName) {
    // One-shot initialization — sufficient given the dialog is keyed on target.
    setName(currentName);
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    const trimmed = name.trim();
    if (!trimmed) {
      toast({ variant: "destructive", title: "Name is required" });
      return;
    }
    try {
      await rename.mutateAsync(trimmed);
      toast({ title: "Credential renamed", description: trimmed });
      setName("");
      onOpenChange(false);
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to rename",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <Dialog
      open={!!target}
      onOpenChange={(open) => {
        if (!open) setName("");
        onOpenChange(open);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rename credential</DialogTitle>
          <DialogDescription>
            Only the name changes — the encrypted value and references stay untouched.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="rename-name">Name</Label>
            <Input
              id="rename-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={rename.isPending}>
              {rename.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RotateCredentialDialog({
  target,
  onOpenChange,
}: {
  target: Credential | null;
  onOpenChange: (open: boolean) => void;
}) {
  const [state, setState] = useState<CredentialFormState>(emptyCredentialForm());
  const rotate = useRotateCredential(target?.id ?? "");
  const { toast } = useToast();

  // Initialize state on target change. Kind + name are locked on rotate;
  // we pass showKindAndName=false to hide those fields in the form.
  if (target && state.kind !== target.kind) {
    setState({ ...emptyCredentialForm(target.kind), name: target.name });
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    const result = buildCredentialRotate(state);
    if (!result.ok) {
      toast({ variant: "destructive", title: result.error });
      return;
    }
    try {
      await rotate.mutateAsync(result.input);
      toast({ title: "Credential rotated", description: target.name });
      setState(emptyCredentialForm());
      onOpenChange(false);
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to rotate",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <Dialog
      open={!!target}
      onOpenChange={(open) => {
        if (!open) setState(emptyCredentialForm());
        onOpenChange(open);
      }}
    >
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Rotate value for “{target?.name}”</DialogTitle>
          <DialogDescription>
            The old secret is overwritten; every repository / app-settings reference stays
            linked to this credential id.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <CredentialFormFields
            idPrefix="rotate-cred"
            state={state}
            onChange={setState}
            showKindAndName={false}
          />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={rotate.isPending}>
              {rotate.isPending ? "Saving…" : "Rotate"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteCredentialDialog({
  target,
  onOpenChange,
}: {
  target: Credential | null;
  onOpenChange: (open: boolean) => void;
}) {
  const del = useDeleteCredential();
  const { toast } = useToast();
  const inUse = target ? target.reference_count > 0 : false;

  const confirmDelete = async () => {
    if (!target) return;
    try {
      await del.mutateAsync(target.id);
      toast({ title: "Credential deleted", description: target.name });
      onOpenChange(false);
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to delete credential",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <Dialog open={!!target} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete credential?</DialogTitle>
          <DialogDescription>
            {target ? (
              inUse ? (
                <>
                  “{target.name}” is still in use. Unlink it from its consumers first.
                </>
              ) : (
                <>“{target.name}” will be removed permanently.</>
              )
            ) : null}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={confirmDelete}
            disabled={del.isPending || inUse}
          >
            {del.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
