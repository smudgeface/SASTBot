import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BookOpen, ShieldCheck } from "lucide-react";

import { ApiError } from "@/api/client";
import { useSetup, useSetupStatus } from "@/api/queries/auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/use-toast";

const PASSWORD_MIN = 12;

export default function SetupPage() {
  const navigate = useNavigate();
  const { data: status, isLoading } = useSetupStatus();

  // Once setup is complete (an admin exists), this screen is no longer valid.
  useEffect(() => {
    if (!isLoading && status && !status.needs_setup) {
      navigate("/login", { replace: true });
    }
  }, [isLoading, status, navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-6">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2 text-primary">
            <ShieldCheck className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-tight">SASTBot</span>
          </div>
          <CardTitle className="text-lg">Welcome — let's set up SASTBot</CardTitle>
          <CardDescription>
            This instance has no users yet. Create the first administrator account, or restore
            an existing backup to migrate from another installation.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="create">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="create">Create admin</TabsTrigger>
              <TabsTrigger value="restore">Restore a backup</TabsTrigger>
            </TabsList>
            <TabsContent value="create" className="pt-4">
              <CreateAdminForm />
            </TabsContent>
            <TabsContent value="restore" className="pt-4">
              <SetupRestoreForm />
            </TabsContent>
          </Tabs>
          <div className="mt-4 border-t border-border pt-3 text-center text-xs text-muted-foreground">
            <Link to="/manual/quick-start" className="inline-flex items-center gap-1 text-primary hover:underline">
              <BookOpen className="h-3 w-3" />
              Read the quick-start guide
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// --------------------------------------------------------------------------
// Create the first admin account
// --------------------------------------------------------------------------

function CreateAdminForm() {
  const navigate = useNavigate();
  const setup = useSetup();
  const { toast } = useToast();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const passwordTooShort = password.length > 0 && password.length < PASSWORD_MIN;
  const mismatch = confirm.length > 0 && confirm !== password;
  const canSubmit =
    email.trim().length > 0 && password.length >= PASSWORD_MIN && confirm === password && !setup.isPending;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    try {
      await setup.mutateAsync({ email: email.trim(), password });
      // Auto-logged-in by the backend — go straight into the app.
      navigate("/", { replace: true });
    } catch (err) {
      const description =
        err instanceof ApiError
          ? err.status === 409
            ? "Setup has already been completed. Redirecting to sign-in…"
            : err.message
          : "Something went wrong. Please try again.";
      toast({ variant: "destructive", title: "Setup failed", description });
      if (err instanceof ApiError && err.status === 409) {
        navigate("/login", { replace: true });
      }
    }
  };

  return (
    <form className="space-y-4" onSubmit={onSubmit} noValidate>
      <div className="space-y-1.5">
        <Label htmlFor="setup-email">Admin email</Label>
        <Input
          id="setup-email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="setup-password">Password</Label>
        <Input
          id="setup-password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <p className={`text-xs ${passwordTooShort ? "text-destructive" : "text-muted-foreground"}`}>
          At least {PASSWORD_MIN} characters.
        </p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="setup-confirm">Confirm password</Label>
        <Input
          id="setup-confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
        {mismatch && <p className="text-xs text-destructive">Passwords do not match.</p>}
      </div>
      <Button type="submit" className="w-full" disabled={!canSubmit}>
        {setup.isPending ? "Creating account…" : "Create admin & sign in"}
      </Button>
    </form>
  );
}

// --------------------------------------------------------------------------
// Restore a backup during the setup window (no admin exists yet)
// --------------------------------------------------------------------------

type RestorePhase = "idle" | "uploading" | "restarting" | "error";

function SetupRestoreForm() {
  const [phase, setPhase] = useState<RestorePhase>("idle");
  const [file, setFile] = useState<File | null>(null);
  const [oldMasterKey, setOldMasterKey] = useState("");
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const startPolling = useCallback(() => {
    pollRef.current = setInterval(() => {
      fetch("/healthz", { cache: "no-store" })
        .then((r) => {
          if (r.ok) {
            if (pollRef.current) clearInterval(pollRef.current);
            // The restored backup carries its own admin — reload lands on /login.
            window.location.assign("/login");
          }
        })
        .catch(() => undefined);
    }, 2000);
  }, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file || phase === "uploading") return;
    setPhase("uploading");
    setErrorDetail(null);

    const formData = new FormData();
    // old_master_key MUST precede the file part (backend reads pre-file fields).
    if (oldMasterKey.trim()) formData.append("old_master_key", oldMasterKey.trim());
    formData.append("file", file, file.name);

    try {
      const resp = await fetch("/api/admin/db/restore?mode=full", {
        method: "POST",
        body: formData,
        credentials: "include",
      });
      if (resp.ok) {
        setPhase("restarting");
        startPolling();
      } else {
        const body = (await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` }))) as { detail?: string };
        setErrorDetail(body.detail ?? `HTTP ${resp.status}`);
        setPhase("error");
      }
    } catch (err) {
      setErrorDetail(err instanceof Error ? err.message : "Network error");
      setPhase("error");
    }
  };

  if (phase === "restarting") {
    return (
      <div className="rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950 px-4 py-3 space-y-2">
        <p className="text-sm font-medium text-amber-800 dark:text-amber-300">Restoring &amp; restarting…</p>
        <p className="text-xs text-amber-700 dark:text-amber-400">
          The backup is being restored and the backend is restarting. This page will move to the
          sign-in screen automatically — log in with the admin account from your backup.
        </p>
      </div>
    );
  }

  return (
    <form className="space-y-4" onSubmit={onSubmit}>
      <p className="text-xs text-muted-foreground">
        Migrating from another installation? Restore a full <code className="font-mono">.tar.gz</code>{" "}
        backup. Your user accounts, settings, and findings come with it. After it restarts, sign in
        with the admin account from that backup.
      </p>
      <div className="space-y-1.5">
        <Label htmlFor="setup-restore-file">Backup file</Label>
        <Input
          id="setup-restore-file"
          type="file"
          accept=".tar.gz,.dump,application/gzip,application/octet-stream"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="text-sm file:mr-2 file:rounded file:border file:border-input file:bg-transparent file:px-2 file:py-1 file:text-xs file:font-medium"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="setup-restore-key" className="text-xs font-medium">
          Source MASTER_KEY{" "}
          <span className="font-normal text-muted-foreground">(only if the backup is from a different key)</span>
        </Label>
        <Input
          id="setup-restore-key"
          type="password"
          autoComplete="off"
          value={oldMasterKey}
          onChange={(e) => setOldMasterKey(e.target.value)}
          placeholder="base64 of the source instance's 32-byte key"
          className="font-mono text-xs"
        />
        <p className="text-xs text-muted-foreground">
          Leave blank if this instance already runs the same MASTER_KEY the backup was taken under.
        </p>
      </div>
      {phase === "error" && errorDetail && (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          <p className="font-medium">Restore failed</p>
          <p className="mt-1 whitespace-pre-wrap break-all">{errorDetail}</p>
        </div>
      )}
      <Button type="submit" variant="destructive" className="w-full" disabled={!file || phase === "uploading"}>
        {phase === "uploading" ? "Uploading…" : "Restore backup"}
      </Button>
    </form>
  );
}
