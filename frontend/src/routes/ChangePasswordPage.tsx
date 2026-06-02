import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { KeyRound, ShieldCheck } from "lucide-react";

import { ApiError } from "@/api/client";
import { useChangePassword, useMe } from "@/api/queries/auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/use-toast";

const PASSWORD_MIN = 12;

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const { data: user, isLoading } = useMe();
  const change = useChangePassword();
  const { toast } = useToast();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");

  if (!isLoading && !user) {
    navigate("/login", { replace: true });
    return null;
  }
  const forced = !!user?.must_change_password;

  const tooShort = next.length > 0 && next.length < PASSWORD_MIN;
  const mismatch = confirm.length > 0 && confirm !== next;
  const sameAsCurrent = next.length > 0 && next === current;
  const canSubmit =
    current.length > 0 && next.length >= PASSWORD_MIN && confirm === next && !sameAsCurrent && !change.isPending;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    try {
      await change.mutateAsync({ current_password: current, new_password: next });
      toast({ title: "Password changed", description: "Your password has been updated." });
      navigate("/", { replace: true });
    } catch (err) {
      const description =
        err instanceof ApiError
          ? err.status === 400
            ? (err.body as { detail?: string })?.detail ?? "Check your current password and try again."
            : err.message
          : "Something went wrong. Please try again.";
      toast({ variant: "destructive", title: "Couldn't change password", description });
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2 text-primary">
            <ShieldCheck className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-tight">SASTBot</span>
          </div>
          <CardTitle className="flex items-center gap-2 text-lg">
            <KeyRound className="h-4 w-4" /> Change password
          </CardTitle>
          <CardDescription>
            {forced
              ? "Your account was set up with a temporary password. Set your own password to continue."
              : "Update the password for your account."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit} noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="cp-current">{forced ? "Temporary password" : "Current password"}</Label>
              <Input
                id="cp-current"
                type="password"
                autoComplete="current-password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-new">New password</Label>
              <Input
                id="cp-new"
                type="password"
                autoComplete="new-password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                required
              />
              <p className={`text-xs ${tooShort ? "text-destructive" : "text-muted-foreground"}`}>
                At least {PASSWORD_MIN} characters.
              </p>
              {sameAsCurrent && <p className="text-xs text-destructive">Must differ from your current password.</p>}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cp-confirm">Confirm new password</Label>
              <Input
                id="cp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
              />
              {mismatch && <p className="text-xs text-destructive">Passwords do not match.</p>}
            </div>
            <Button type="submit" className="w-full" disabled={!canSubmit}>
              {change.isPending ? "Saving…" : "Change password"}
            </Button>
          </form>
          {!forced && (
            <div className="mt-4 border-t border-border pt-3 text-center text-xs text-muted-foreground">
              <Link to="/" className="text-primary hover:underline">
                Back to SASTBot
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
