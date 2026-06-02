import { useState } from "react";

import { ApiError } from "@/api/client";
import { useMe } from "@/api/queries/auth";
import {
  useCreateUser,
  useDeleteUser,
  useResetUserPassword,
  useUpdateUser,
  useUsers,
} from "@/api/queries/users";
import type { AdminUser } from "@/api/types";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";

const PASSWORD_MIN = 12;

function randomPassword(): string {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

function apiErr(err: unknown, fallback: string): string {
  return err instanceof ApiError
    ? ((err.body as { detail?: string })?.detail ?? err.message)
    : fallback;
}

export default function UsersPage() {
  const { data: me } = useMe();
  const { data: users, isLoading } = useUsers();
  const { toast } = useToast();

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<AdminUser | null>(null);
  const [resetUser, setResetUser] = useState<AdminUser | null>(null);
  const [deleteUser, setDeleteUser] = useState<AdminUser | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Users</h1>
          <p className="text-sm text-muted-foreground">
            Manage local accounts. New and reset accounts get a one-time password — the user must
            set their own on first login.
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>Add user</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Accounts</CardTitle>
          <CardDescription>
            {users ? `${users.length} user${users.length === 1 ? "" : "s"}` : "Loading…"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last login</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">Loading…</TableCell>
                </TableRow>
              )}
              {users?.map((u) => {
                const isSelf = me?.id === u.id;
                return (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium">
                      {u.email}
                      {isSelf && <Badge variant="outline" className="ml-2">you</Badge>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{u.name ?? "—"}</TableCell>
                    <TableCell>
                      <Badge variant={u.role === "admin" ? "default" : "secondary"}>{u.role}</Badge>
                    </TableCell>
                    <TableCell className="space-x-1">
                      {u.is_active ? (
                        <Badge variant="secondary">active</Badge>
                      ) : (
                        <Badge variant="outline" className="text-destructive border-destructive/40">disabled</Badge>
                      )}
                      {u.must_change_password && (
                        <Badge variant="outline" className="text-amber-600 border-amber-400">must change pw</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "never"}
                    </TableCell>
                    <TableCell className="text-right space-x-2 whitespace-nowrap">
                      <Button variant="ghost" size="sm" onClick={() => setEditUser(u)}>Edit</Button>
                      <Button variant="ghost" size="sm" onClick={() => setResetUser(u)}>Reset pw</Button>
                      <Button variant="ghost" size="sm" className="text-destructive" onClick={() => setDeleteUser(u)} disabled={isSelf}>Delete</Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <CreateUserDialog open={createOpen} onClose={() => setCreateOpen(false)} toast={toast} />
      {editUser && (
        <EditUserDialog
          user={editUser}
          isSelf={me?.id === editUser.id}
          onClose={() => setEditUser(null)}
          toast={toast}
        />
      )}
      {resetUser && <ResetPasswordDialog user={resetUser} onClose={() => setResetUser(null)} toast={toast} />}
      {deleteUser && <DeleteUserDialog user={deleteUser} onClose={() => setDeleteUser(null)} toast={toast} />}
    </div>
  );
}

type Toast = ReturnType<typeof useToast>["toast"];

function CreateUserDialog({ open, onClose, toast }: { open: boolean; onClose: () => void; toast: Toast }) {
  const create = useCreateUser();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<"admin" | "user">("user");
  const [password, setPassword] = useState("");

  const valid = email.includes("@") && password.length >= PASSWORD_MIN && !create.isPending;

  const submit = async () => {
    if (!valid) return;
    try {
      await create.mutateAsync({ email: email.trim(), name: name.trim() || undefined, role, password });
      toast({ title: "User created", description: `${email} — share the temporary password securely.` });
      onClose();
    } catch (err) {
      toast({ variant: "destructive", title: "Couldn't create user", description: apiErr(err, "Try again.") });
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add user</DialogTitle>
          <DialogDescription>
            The user signs in with this one-time password and is required to set their own.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="nu-email">Email</Label>
            <Input id="nu-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nu-name">Name (optional)</Label>
            <Input id="nu-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as "admin" | "user")}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="user">User — view &amp; run scans</SelectItem>
                <SelectItem value="admin">Admin — full access</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nu-pw">Temporary password</Label>
            <div className="flex gap-2">
              <Input id="nu-pw" value={password} onChange={(e) => setPassword(e.target.value)} className="font-mono text-xs" />
              <Button type="button" variant="outline" size="sm" onClick={() => setPassword(randomPassword())}>Generate</Button>
            </div>
            <p className="text-xs text-muted-foreground">At least {PASSWORD_MIN} characters.</p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={!valid}>{create.isPending ? "Creating…" : "Create user"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EditUserDialog({
  user,
  isSelf,
  onClose,
  toast,
}: {
  user: AdminUser;
  isSelf: boolean;
  onClose: () => void;
  toast: Toast;
}) {
  const update = useUpdateUser();
  const [name, setName] = useState(user.name ?? "");
  const [role, setRole] = useState<"admin" | "user">(user.role === "admin" ? "admin" : "user");
  const [isActive, setIsActive] = useState(user.is_active);

  const submit = async () => {
    try {
      await update.mutateAsync({
        id: user.id,
        name: name.trim() || null,
        // Don't submit role/active for your own account — you can't change them,
        // and omitting them keeps the request a clean name-only edit.
        ...(isSelf ? {} : { role, is_active: isActive }),
      });
      toast({ title: "User updated", description: user.email });
      onClose();
    } catch (err) {
      toast({ variant: "destructive", title: "Couldn't update user", description: apiErr(err, "Try again.") });
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Edit {user.email}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="eu-name">Name</Label>
            <Input id="eu-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as "admin" | "user")} disabled={isSelf}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="user">User</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={isActive}
              onChange={(e) => setIsActive(e.target.checked)}
              disabled={isSelf}
            />
            Active (uncheck to disable sign-in)
          </label>
          {isSelf && (
            <p className="text-xs text-muted-foreground">
              You can't change your own role or active status — ask another admin.
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={update.isPending}>{update.isPending ? "Saving…" : "Save"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordDialog({ user, onClose, toast }: { user: AdminUser; onClose: () => void; toast: Toast }) {
  const reset = useResetUserPassword();
  const [password, setPassword] = useState("");
  const valid = password.length >= PASSWORD_MIN && !reset.isPending;

  const submit = async () => {
    if (!valid) return;
    try {
      await reset.mutateAsync({ id: user.id, password });
      toast({ title: "Password reset", description: `${user.email} must set a new password on next login.` });
      onClose();
    } catch (err) {
      toast({ variant: "destructive", title: "Couldn't reset password", description: apiErr(err, "Try again.") });
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Reset password — {user.email}</DialogTitle>
          <DialogDescription>
            Sets a one-time password and signs the user out everywhere. They must set their own on next login.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="rp-pw">Temporary password</Label>
          <div className="flex gap-2">
            <Input id="rp-pw" value={password} onChange={(e) => setPassword(e.target.value)} className="font-mono text-xs" />
            <Button type="button" variant="outline" size="sm" onClick={() => setPassword(randomPassword())}>Generate</Button>
          </div>
          <p className="text-xs text-muted-foreground">At least {PASSWORD_MIN} characters.</p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={!valid}>{reset.isPending ? "Resetting…" : "Reset password"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DeleteUserDialog({ user, onClose, toast }: { user: AdminUser; onClose: () => void; toast: Toast }) {
  const del = useDeleteUser();
  const submit = async () => {
    try {
      await del.mutateAsync(user.id);
      toast({ title: "User deleted", description: user.email });
      onClose();
    } catch (err) {
      toast({ variant: "destructive", title: "Couldn't delete user", description: apiErr(err, "Try again.") });
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Delete {user.email}?</DialogTitle>
          <DialogDescription>This permanently removes the account and its sessions. This cannot be undone.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => void submit()} disabled={del.isPending}>
            {del.isPending ? "Deleting…" : "Delete user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
