import { useState } from "react";
import { Trash2 } from "lucide-react";

import { useCredentials, useDeleteCredential } from "@/api/queries/credentials";
import type { Credential } from "@/api/types";
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
  const deleteCredential = useDeleteCredential();
  const { toast } = useToast();
  const [pendingDelete, setPendingDelete] = useState<Credential | null>(null);

  const items = credentials.data ?? [];

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteCredential.mutateAsync(pendingDelete.id);
      toast({ title: "Credential deleted", description: pendingDelete.label });
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to delete credential",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setPendingDelete(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Credentials</h1>
        <p className="text-sm text-muted-foreground">
          Credential values are encrypted in the database and cannot be viewed after creation. To
          replace a value, create a new credential and delete the old one.
        </p>
      </div>

      {!credentials.isLoading && items.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>No credentials</CardTitle>
            <CardDescription>
              Credentials are created inline when adding a repository or saving integration
              settings.
            </CardDescription>
          </CardHeader>
          <CardContent />
        </Card>
      ) : null}

      {items.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Label</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {truncate(c.id, 10)}
                  </TableCell>
                  <TableCell className="uppercase">{c.kind}</TableCell>
                  <TableCell>{c.label}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(c.created_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setPendingDelete(c)}
                      aria-label={`Delete credential ${c.label}`}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      ) : null}

      <Dialog open={!!pendingDelete} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete credential?</DialogTitle>
            <DialogDescription>
              {pendingDelete
                ? `“${pendingDelete.label}” will be removed. Any integration using it will need to be updated.`
                : null}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingDelete(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
              disabled={deleteCredential.isPending}
            >
              {deleteCredential.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
