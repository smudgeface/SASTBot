import { useCallback, useEffect, useRef, useState } from "react";

import { useCredentials } from "@/api/queries/credentials";
import { useSettings, useUpdateSettings, useCheckLlm } from "@/api/queries/settings";
import { useCheckJiraConnection } from "@/api/queries/jira";
import { useVersion } from "@/api/queries/version";
import type { AdminSettingsUpdate, LlmApiFormat, ReachabilityMinSeverity } from "@/api/types";
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
import { useToast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";

const LLM_DEFAULTS = {
  base_url: "https://llm.internal.example",
  api_format: "anthropic-messages" as LlmApiFormat,
  model: "claude-opus-4-7",
};

type CredentialChoice = "existing" | "new";

export default function SettingsPage() {
  const settings = useSettings();
  const credentials = useCredentials();
  const updateSettings = useUpdateSettings();
  const checkLlm = useCheckLlm();
  const checkJira = useCheckJiraConnection();
  const versionInfo = useVersion();
  const { toast } = useToast();

  // Jira section state
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraCredChoice, setJiraCredChoice] = useState<CredentialChoice>("existing");
  const [jiraCredId, setJiraCredId] = useState<string>("");
  const [jiraNewName, setJiraNewName] = useState("");
  const [jiraNewValue, setJiraNewValue] = useState("");

  // LLM connection section state
  const [llmBaseUrl, setLlmBaseUrl] = useState(LLM_DEFAULTS.base_url);
  const [llmApiFormat, setLlmApiFormat] = useState<LlmApiFormat>(LLM_DEFAULTS.api_format);
  const [llmModel, setLlmModel] = useState(LLM_DEFAULTS.model);
  const [llmCredChoice, setLlmCredChoice] = useState<CredentialChoice>("existing");
  const [llmCredId, setLlmCredId] = useState<string>("");
  const [llmNewName, setLlmNewName] = useState("");
  const [llmNewValue, setLlmNewValue] = useState("");

  // LLM assistance section state
  const [reachabilityMinSeverity, setReachabilityMinSeverity] = useState<ReachabilityMinSeverity>("high");

  // NVD API key section state
  const [nvdCredChoice, setNvdCredChoice] = useState<CredentialChoice>("existing");
  const [nvdCredId, setNvdCredId] = useState<string>("");
  const [nvdNewName, setNvdNewName] = useState("");
  const [nvdNewValue, setNvdNewValue] = useState("");

  // When the settings query completes, hydrate the form.
  useEffect(() => {
    const data = settings.data;
    if (!data) return;
    setJiraBaseUrl(data.jira_base_url ?? "");
    setJiraEmail(data.jira_email ?? "");
    setJiraCredId(data.jira_credential_id ?? "");
    setJiraCredChoice(data.jira_credential_id ? "existing" : "new");

    setLlmBaseUrl(data.llm_base_url || LLM_DEFAULTS.base_url);
    setLlmApiFormat((data.llm_api_format as LlmApiFormat) || LLM_DEFAULTS.api_format);
    setLlmModel(data.llm_model || LLM_DEFAULTS.model);
    setLlmCredId(data.llm_credential_id ?? "");
    setLlmCredChoice(data.llm_credential_id ? "existing" : "new");

    setReachabilityMinSeverity(data.reachability_min_severity ?? "high");

    setNvdCredId(data.nvd_credential_id ?? "");
    setNvdCredChoice(data.nvd_credential_id ? "existing" : "new");
  }, [settings.data]);

  const jiraOptions = credentials.data?.items.filter((c) => c.kind.startsWith("jira")) ?? [];
  const llmOptions = credentials.data?.items.filter((c) => c.kind === "llm_api_key") ?? [];
  const nvdOptions = credentials.data?.items.filter((c) => c.kind === "nvd_api_key") ?? [];
  const credentialsLoading = credentials.isLoading;

  const buildJiraCred = (): AdminSettingsUpdate["jira_credential"] => {
    if (jiraCredChoice !== "new") return null;
    if (!jiraNewName.trim() || !jiraNewValue.trim()) return null;
    return {
      kind: "jira_token",
      name: jiraNewName.trim(),
      value: jiraNewValue,
    };
  };

  const buildLlmCred = (): AdminSettingsUpdate["llm_credential"] => {
    if (llmCredChoice !== "new") return null;
    if (!llmNewName.trim() || !llmNewValue.trim()) return null;
    return {
      kind: "llm_api_key",
      name: llmNewName.trim(),
      value: llmNewValue,
    };
  };

  const buildNvdCred = (): AdminSettingsUpdate["nvd_credential"] => {
    if (nvdCredChoice !== "new") return null;
    if (!nvdNewName.trim() || !nvdNewValue.trim()) return null;
    return {
      kind: "nvd_api_key",
      name: nvdNewName.trim(),
      value: nvdNewValue,
    };
  };

  const buildPayload = (): AdminSettingsUpdate => {
    const jiraCred = buildJiraCred();
    const llmCred = buildLlmCred();
    const nvdCred = buildNvdCred();
    const payload: AdminSettingsUpdate = {
      jira_base_url: jiraBaseUrl.trim() || null,
      jira_email: jiraEmail.trim() || null,
      llm_base_url: llmBaseUrl.trim() || null,
      llm_api_format: llmApiFormat,
      llm_model: llmModel.trim() || null,
      reachability_min_severity: reachabilityMinSeverity,
    };
    // Only include credential keys when the user is actually making a change.
    // If choice is "existing" but no credential is selected (form not yet
    // hydrated, or no creds exist), omit the field so the backend leaves
    // whatever is currently linked alone — sending null here would silently
    // disconnect a credential the user hasn't touched. To clear a credential,
    // the operator deletes the credential row directly (FK is ON DELETE SET NULL).
    if (jiraCredChoice === "existing" && jiraCredId) {
      payload.jira_credential_id = jiraCredId;
    } else if (jiraCred) {
      payload.jira_credential = jiraCred;
    }
    if (llmCredChoice === "existing" && llmCredId) {
      payload.llm_credential_id = llmCredId;
    } else if (llmCred) {
      payload.llm_credential = llmCred;
    }
    if (nvdCredChoice === "existing" && nvdCredId) {
      payload.nvd_credential_id = nvdCredId;
    } else if (nvdCred) {
      payload.nvd_credential = nvdCred;
    }
    return payload;
  };

  /** Save current form state; used by Save and by the Check-connection buttons
   *  so users don't need to remember to click Save before testing. */
  const persist = async (): Promise<boolean> => {
    try {
      const updated = await updateSettings.mutateAsync(buildPayload());
      // Clear fresh credential fields after save to avoid re-submitting them.
      setJiraNewName("");
      setJiraNewValue("");
      setLlmNewName("");
      setLlmNewValue("");
      setNvdNewName("");
      setNvdNewValue("");
      // If a new credential was created, reset choice to "existing" and point
      // at the new credential id so subsequent saves don't try to re-create.
      if (updated.jira_credential_id) {
        setJiraCredChoice("existing");
        setJiraCredId(updated.jira_credential_id);
      }
      if (updated.llm_credential_id) {
        setLlmCredChoice("existing");
        setLlmCredId(updated.llm_credential_id);
      }
      if (updated.nvd_credential_id) {
        setNvdCredChoice("existing");
        setNvdCredId(updated.nvd_credential_id);
      }
      return true;
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to save settings",
        description: err instanceof Error ? err.message : "Unknown error",
      });
      return false;
    }
  };

  const onSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await persist()) toast({ title: "Settings saved" });
  };

  const onCheckJira = async () => {
    if (await persist()) checkJira.mutate();
  };

  const onCheckLlm = async () => {
    if (await persist()) checkLlm.mutate();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Configure the integrations SASTBot relies on.
        </p>
      </div>

      <form className="space-y-6" onSubmit={onSave}>
        <Card>
          <CardHeader>
            <CardTitle>Jira</CardTitle>
            <CardDescription>Used to open tickets for triaged findings.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="jira-url">Base URL</Label>
                <Input
                  id="jira-url"
                  value={jiraBaseUrl}
                  onChange={(e) => setJiraBaseUrl(e.target.value)}
                  placeholder="https://yourorg.atlassian.net"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="jira-email">Account email</Label>
                <Input
                  id="jira-email"
                  type="email"
                  value={jiraEmail}
                  onChange={(e) => setJiraEmail(e.target.value)}
                  placeholder="you@example.com"
                />
              </div>
            </div>

            <CredentialPicker
              idPrefix="jira"
              choice={jiraCredChoice}
              setChoice={setJiraCredChoice}
              credentialId={jiraCredId}
              setCredentialId={setJiraCredId}
              options={jiraOptions}
              newName={jiraNewName}
              setNewName={setJiraNewName}
              newValue={jiraNewValue}
              setNewValue={setJiraNewValue}
              valuePlaceholder="Jira API token"
              kindLabel="Jira token"
              isLoading={credentialsLoading}
            />

            <div className="flex items-center gap-3">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={checkJira.isPending || updateSettings.isPending}
                onClick={onCheckJira}
                title="Saves settings and then tests the connection"
              >
                {updateSettings.isPending ? "Saving…" : checkJira.isPending ? "Checking…" : "Save & test connection"}
              </Button>
              {checkJira.data && (
                <span className={`text-sm ${checkJira.data.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}>
                  {checkJira.data.ok
                    ? `✓ Connected as ${checkJira.data.account_name}`
                    : `✗ ${checkJira.data.error}`}
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>LLM gateway</CardTitle>
            <CardDescription>
              Central gateway used by SASTBot for all LLM calls.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="llm-url">Base URL</Label>
                <Input
                  id="llm-url"
                  value={llmBaseUrl}
                  onChange={(e) => setLlmBaseUrl(e.target.value)}
                  placeholder={LLM_DEFAULTS.base_url}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="llm-format">API format</Label>
                <Select
                  value={llmApiFormat}
                  onValueChange={(v) => setLlmApiFormat(v as LlmApiFormat)}
                >
                  <SelectTrigger id="llm-format">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="anthropic-messages">anthropic-messages</SelectItem>
                    <SelectItem value="openai-completions">openai-completions</SelectItem>
                    <SelectItem value="openai-chat">openai-chat</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="llm-model">Model</Label>
                <Input
                  id="llm-model"
                  value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)}
                  placeholder={LLM_DEFAULTS.model}
                />
              </div>
            </div>

            <Separator />

            <CredentialPicker
              idPrefix="llm"
              choice={llmCredChoice}
              setChoice={setLlmCredChoice}
              credentialId={llmCredId}
              setCredentialId={setLlmCredId}
              options={llmOptions}
              newName={llmNewName}
              setNewName={setLlmNewName}
              newValue={llmNewValue}
              setNewValue={setLlmNewValue}
              valuePlaceholder="API key"
              kindLabel="LLM API key"
              isLoading={credentialsLoading}
            />

            <Separator />

            {/* Connection check */}
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={checkLlm.isPending || updateSettings.isPending}
                  onClick={onCheckLlm}
                  title="Saves settings and then tests the connection"
                >
                  {updateSettings.isPending ? "Saving…" : checkLlm.isPending ? "Checking…" : "Save & test connection"}
                </Button>
                {checkLlm.data ? (
                  <span
                    className={cn(
                      "text-xs font-medium",
                      checkLlm.data.success
                        ? "text-emerald-600 dark:text-emerald-400"
                        : "text-destructive",
                    )}
                  >
                    {checkLlm.data.success ? "Connected" : "Failed"}
                  </span>
                ) : null}
              </div>
              {checkLlm.data ? (
                <div className="rounded border bg-muted/40 px-3 py-2 text-xs space-y-0.5">
                  {checkLlm.data.success ? (
                    <>
                      <p>Model: <span className="font-mono">{checkLlm.data.model}</span></p>
                      <p>Latency: {checkLlm.data.latency_ms}ms</p>
                      <p>Tokens: {checkLlm.data.input_tokens} in / {checkLlm.data.output_tokens} out</p>
                    </>
                  ) : (
                    <p className="text-destructive">{checkLlm.data.error}</p>
                  )}
                </div>
              ) : null}
            </div>
          </CardContent>
        </Card>

        {/* LLM-assisted analysis */}
        <Card>
          <CardHeader>
            <CardTitle>LLM-assisted analysis</CardTitle>
            <CardDescription>
              LLM analysis is required — configure the gateway above to enable SAST triage, reachability analysis, and issue summaries.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            {/* Warn if no credential configured */}
            {!settings.data?.llm_credential_id && llmCredChoice !== "new" ? (
              <p className="text-xs text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900 rounded px-3 py-2 bg-amber-50 dark:bg-amber-950">
                LLM credentials not configured — set up a credential in the LLM gateway section above. Scans will not run without a working LLM connection.
              </p>
            ) : null}

            <Separator />

            {/* Threshold */}
            <div className="space-y-1.5">
              <Label htmlFor="reach-sev">Reachability minimum severity</Label>
              <select
                id="reach-sev"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={reachabilityMinSeverity}
                onChange={(e) => setReachabilityMinSeverity(e.target.value as ReachabilityMinSeverity)}
              >
                <option value="critical">Critical only</option>
                <option value="high">High and above</option>
                <option value="medium">Medium and above</option>
                <option value="low">Low and above</option>
              </select>
              <p className="text-xs text-muted-foreground">
                Only CVE findings at this severity or higher will be assessed for reachability.
                Per-repo SAST effort and token budgets live on each repo's edit page.
              </p>
            </div>

          </CardContent>
        </Card>

        {/* NVD API key */}
        <Card>
          <CardHeader>
            <CardTitle>NVD API key</CardTitle>
            <CardDescription>
              Optional. Raises the NVD rate limit from 5 req/30 s to 50 req/30 s.
              Without a key SASTBot still queries NVD for C/C++ components —
              it just throttles more conservatively. Obtain a key at{" "}
              <a
                href="https://nvd.nist.gov/developers/request-an-api-key"
                target="_blank"
                rel="noreferrer"
                className="underline"
              >
                nvd.nist.gov
              </a>
              .
            </CardDescription>
          </CardHeader>
          <CardContent>
            <CredentialPicker
              idPrefix="nvd"
              choice={nvdCredChoice}
              setChoice={setNvdCredChoice}
              credentialId={nvdCredId}
              setCredentialId={setNvdCredId}
              options={nvdOptions}
              newName={nvdNewName}
              setNewName={setNvdNewName}
              newValue={nvdNewValue}
              setNewValue={setNvdNewValue}
              valuePlaceholder="NVD API key"
              kindLabel="NVD API key"
              isLoading={credentialsLoading}
            />
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button type="submit" disabled={updateSettings.isPending}>
            {updateSettings.isPending ? "Saving…" : "Save settings"}
          </Button>
        </div>
      </form>

      {/* Database backup & restore — outside the settings form so it can't be
          accidentally triggered by pressing Enter on a form field */}
      <Card>
        <CardHeader>
          <CardTitle>Database backup &amp; restore</CardTitle>
          <CardDescription>
            Download or restore a complete backup of the application database.
            The backup is a <code className="font-mono text-xs">.tar.gz</code> archive containing
            a PostgreSQL custom-format dump and version metadata.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Backup */}
          <div>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                const a = document.createElement("a");
                a.href = "/api/admin/db/backup";
                a.download = "";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
              }}
            >
              Download backup
            </Button>
            <p className="mt-2 text-xs text-muted-foreground">
              Produces a <code className="font-mono">sastbot-backup-*.tar.gz</code> archive
              containing <code className="font-mono">dump.pgcustom</code> and{" "}
              <code className="font-mono">metadata.json</code> with version info.
            </p>
          </div>

          <Separator />

          {/* Restore */}
          <RestoreSection />
        </CardContent>
      </Card>

      {/* Version footer */}
      <div className="pt-2 pb-4">
        {versionInfo.data ? (
          <p className={cn(
            "text-xs text-muted-foreground",
            versionInfo.data.schema !== versionInfo.data.expected_schema
              ? "text-amber-600 dark:text-amber-400"
              : "",
          )}>
            SASTBot v{versionInfo.data.app}
            {" · "}
            schema{" "}
            <span className="font-mono">{versionInfo.data.schema.slice(0, 14)}</span>
            {versionInfo.data.schema !== versionInfo.data.expected_schema ? (
              <>
                {" · "}expected{" "}
                <span className="font-mono">{versionInfo.data.expected_schema.slice(0, 14)}</span>
                {" "}— schema mismatch, migration may be pending
              </>
            ) : null}
          </p>
        ) : null}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// DB Restore subcomponent
// --------------------------------------------------------------------------

type RestoreMode = "full" | "runtime";

type RestorePhase =
  | "idle"
  | "confirming"   // modal open, waiting for confirmation
  | "uploading"    // file is being uploaded to the backend
  | "restarting"   // upload succeeded; polling /healthz
  | "error";       // restore failed

function RestoreSection() {
  const { toast } = useToast();
  const [phase, setPhase] = useState<RestorePhase>("idle");
  const [restoreMode, setRestoreMode] = useState<RestoreMode>("full");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [migrationWarning, setMigrationWarning] = useState<string | null>(null);
  const [migrationsApplied, setMigrationsApplied] = useState<string[]>([]);
  const [appVersionWarning, setAppVersionWarning] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const resetState = useCallback(() => {
    setPhase("idle");
    setSelectedFile(null);
    setConfirmText("");
    setErrorDetail(null);
    setMigrationWarning(null);
    setMigrationsApplied([]);
    setAppVersionWarning(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
    // intentionally do NOT reset restoreMode — let the operator keep their selection
  }, []);

  // Poll /healthz after a successful restore until the backend comes back up.
  const startPolling = useCallback(() => {
    pollRef.current = setInterval(() => {
      fetch("/healthz", { cache: "no-store" })
        .then((r) => {
          if (r.ok) {
            if (pollRef.current) clearInterval(pollRef.current);
            // Reload the page so stale TanStack Query caches are cleared and
            // the user gets a fresh session check.
            window.location.reload();
          }
        })
        .catch(() => {
          // backend not yet up — keep polling
        });
    }, 2000);
  }, []);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null;
    setSelectedFile(file);
  };

  const openModal = () => {
    if (!selectedFile) {
      toast({ variant: "destructive", title: "No file selected", description: "Choose a .tar.gz backup or legacy .dump file first." });
      return;
    }
    setConfirmText("");
    setErrorDetail(null);
    setMigrationWarning(null);
    setPhase("confirming");
  };

  const onConfirmRestore = async () => {
    if (!selectedFile || confirmText !== "RESTORE") return;
    setPhase("uploading");

    const formData = new FormData();
    formData.append("file", selectedFile, selectedFile.name);

    try {
      const resp = await fetch(`/api/admin/db/restore?mode=${restoreMode}`, {
        method: "POST",
        body: formData,
        credentials: "include",
      });

      if (resp.ok) {
        const body = await resp.json() as {
          ok: boolean;
          restarting: boolean;
          migrations_applied?: string[];
          migration_warning?: string;
          app_version_warning?: string;
        };
        if (body.migration_warning) setMigrationWarning(body.migration_warning);
        if (body.migrations_applied) setMigrationsApplied(body.migrations_applied);
        if (body.app_version_warning) setAppVersionWarning(body.app_version_warning);
        setPhase("restarting");
        startPolling();
      } else {
        const body = await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` })) as { detail?: string };
        setErrorDetail(body.detail ?? `HTTP ${resp.status}`);
        setPhase("error");
      }
    } catch (err) {
      setErrorDetail(err instanceof Error ? err.message : "Network error");
      setPhase("error");
    }
  };

  const isConfirmed = confirmText === "RESTORE";

  // Uploading / restarting states replace the modal body
  if (phase === "restarting") {
    return (
      <div className="rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950 px-4 py-3 space-y-2">
        <p className="text-sm font-medium text-amber-800 dark:text-amber-300">Backend is restarting…</p>
        <p className="text-xs text-amber-700 dark:text-amber-400">
          The restore completed successfully. The backend process is restarting to establish fresh database connections.
          This page will reload automatically once it is reachable again.
        </p>
        {appVersionWarning && (
          <p className="text-xs text-amber-700 dark:text-amber-400 border-t border-amber-200 dark:border-amber-800 pt-2">
            Note: {appVersionWarning}
          </p>
        )}
        {migrationsApplied.length > 0 && (
          <div className="text-xs text-amber-700 dark:text-amber-400 border-t border-amber-200 dark:border-amber-800 pt-2 space-y-0.5">
            <p className="font-medium">Migrations applied ({migrationsApplied.length}):</p>
            {migrationsApplied.map((m) => (
              <p key={m} className="font-mono">{m}</p>
            ))}
          </div>
        )}
        {migrationWarning && (
          <p className="text-xs text-amber-700 dark:text-amber-400 border-t border-amber-200 dark:border-amber-800 pt-2">
            Note: {migrationWarning}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-medium">Restore from backup</p>
        <p className="text-xs text-muted-foreground mt-0.5">
          Upload a <code className="font-mono">.tar.gz</code> backup produced by the "Download backup"
          button above, or a legacy <code className="font-mono">.dump</code> file from a previous
          SASTBot version. The backend will restart after a successful restore.
        </p>
      </div>

      {/* Restore mode selector */}
      <div className="space-y-2" data-testid="restore-mode-group">
        <p className="text-xs font-medium text-foreground">Restore mode</p>
        <div className="space-y-2">
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="radio"
              name="restore-mode"
              value="full"
              checked={restoreMode === "full"}
              onChange={() => setRestoreMode("full")}
              className="mt-0.5"
              data-testid="restore-mode-full"
            />
            <div>
              <span className="text-sm font-medium">Full restore (rebuild from scratch)</span>
              <p className="text-xs text-muted-foreground">
                Replaces the entire database with the backup — use this when recovering from data
                loss or migrating to a new instance.
              </p>
            </div>
          </label>
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="radio"
              name="restore-mode"
              value="runtime"
              checked={restoreMode === "runtime"}
              onChange={() => setRestoreMode("runtime")}
              className="mt-0.5"
              data-testid="restore-mode-runtime"
            />
            <div>
              <span className="text-sm font-medium">Runtime-only restore (undo scan data, keep settings)</span>
              <p className="text-xs text-muted-foreground">
                Preserves your current users, credentials, repos, and app settings while
                restoring scan findings to the backup state — use this to undo a bad scan run
                without losing configuration changes made since the backup.
              </p>
            </div>
          </label>
        </div>
        {restoreMode === "runtime" && (
          <div className="rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            If you have deleted any repos or upgraded the backend since this backup was taken, use
            Full restore instead.
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        <input
          ref={fileInputRef}
          type="file"
          accept=".tar.gz,.dump,application/gzip,application/octet-stream"
          onChange={onFileChange}
          className="text-sm file:mr-2 file:rounded file:border file:border-input file:bg-transparent file:px-2 file:py-1 file:text-xs file:font-medium"
        />
        <Button
          type="button"
          variant="destructive"
          size="sm"
          disabled={!selectedFile || phase === "uploading"}
          onClick={openModal}
        >
          Restore…
        </Button>
      </div>

      {phase === "error" && errorDetail && (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          <p className="font-medium">Restore failed</p>
          <p className="mt-1 whitespace-pre-wrap break-all">{errorDetail}</p>
          <Button type="button" variant="ghost" size="sm" className="mt-2" onClick={resetState}>
            Dismiss
          </Button>
        </div>
      )}

      {/* Two-step confirmation modal */}
      <Dialog open={phase === "confirming" || phase === "uploading"} onOpenChange={(open) => { if (!open && phase === "confirming") resetState(); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Restore database?</DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-3 pt-1">
                <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive font-medium">
                  {restoreMode === "full"
                    ? "This will replace ALL data in the database. This action cannot be undone."
                    : "This will overwrite scan data (findings, scan runs, components) from the backup while keeping your current settings, users, and repos. This action cannot be undone."}
                </div>
                <p className="text-sm">
                  File to restore:{" "}
                  <span className="font-mono text-xs break-all">{selectedFile?.name ?? ""}</span>
                  {selectedFile ? ` (${(selectedFile.size / 1024 / 1024).toFixed(1)} MB)` : ""}
                </p>
                <div className="space-y-1.5">
                  <Label htmlFor="restore-confirm">
                    Type <span className="font-mono font-bold">RESTORE</span> to confirm
                  </Label>
                  <Input
                    id="restore-confirm"
                    value={confirmText}
                    onChange={(e) => setConfirmText(e.target.value)}
                    placeholder="RESTORE"
                    autoComplete="off"
                    disabled={phase === "uploading"}
                  />
                </div>
              </div>
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={resetState}
              disabled={phase === "uploading"}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={() => void onConfirmRestore()}
              disabled={!isConfirmed || phase === "uploading"}
            >
              {phase === "uploading" ? "Uploading…" : "Restore database"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// --------------------------------------------------------------------------
// Credential picker subcomponent
// --------------------------------------------------------------------------

interface CredentialPickerProps {
  idPrefix: string;
  choice: CredentialChoice;
  setChoice: (c: CredentialChoice) => void;
  credentialId: string;
  setCredentialId: (id: string) => void;
  options: { id: string; name: string; kind: string }[];
  newName: string;
  setNewName: (v: string) => void;
  newValue: string;
  setNewValue: (v: string) => void;
  valuePlaceholder: string;
  kindLabel: string;
  /** When true, the existing-credential Select is replaced with a disabled
   *  loading state. Prevents the Radix Select race where `value` is set before
   *  the matching SelectItem mounts (so the trigger displays a blank). */
  isLoading?: boolean;
}

function CredentialPicker({
  idPrefix,
  choice,
  setChoice,
  credentialId,
  setCredentialId,
  options,
  newName,
  setNewName,
  newValue,
  setNewValue,
  valuePlaceholder,
  kindLabel,
  isLoading,
}: CredentialPickerProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <Label className="text-sm font-semibold">Credential</Label>
        <div className="flex gap-3 text-xs">
          <label className="inline-flex items-center gap-1.5">
            <input
              type="radio"
              name={`${idPrefix}-cred-choice`}
              checked={choice === "existing"}
              onChange={() => setChoice("existing")}
            />
            Use existing
          </label>
          <label className="inline-flex items-center gap-1.5">
            <input
              type="radio"
              name={`${idPrefix}-cred-choice`}
              checked={choice === "new"}
              onChange={() => setChoice("new")}
            />
            Create new
          </label>
        </div>
      </div>

      {choice === "existing" ? (
        // Two compounding Radix quirks make this section non-trivial:
        //   (1) On a freshly-mounted Select with a controlled `value` that
        //       has no matching SelectItem yet (because the credentials
        //       query hasn't resolved), Radix can't auto-resolve the trigger
        //       label, AND it fires onValueChange("") to "fix" the
        //       mismatch — which overwrites our hydrated state. Repro:
        //       settings resolves fast, useEffect sets credentialId to
        //       <uuid>, render with empty options → Radix clears it. State
        //       sticks at "" even after credentials arrive.
        //   (2) Even if we sidestep (1), Radix renders the placeholder
        //       instead of the item's text on the first render after a
        //       value→item match, because items register in a useEffect
        //       one render later.
        // Both are addressed below by:
        //   - rendering the label explicitly via SelectValue children
        //     (sidesteps quirk 2)
        //   - ignoring the phantom onValueChange("") when no real options
        //     are registered yet (sidesteps quirk 1)
        //   - showing a "Loading credentials…" pseudo-value while the
        //     credentials query is in flight (covers the original Issue 11
        //     operator-visible bug)
        (() => {
          const selected = options.find((c) => c.id === credentialId);
          const handleValueChange = (v: string) => {
            // Reject Radix's "fix" callback: never accept "" while no real
            // options are mounted. Real user selections only ever come with
            // a non-empty UUID that exists in the rendered options list.
            if (v === "" && options.length === 0) return;
            setCredentialId(v);
          };
          return (
            <Select
              value={credentialId}
              onValueChange={handleValueChange}
              disabled={isLoading}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select a credential">
                  {isLoading ? (
                    "Loading credentials…"
                  ) : selected ? (
                    <>
                      {selected.name} — <span className="text-muted-foreground">{selected.kind}</span>
                    </>
                  ) : null}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                {options.length === 0 ? (
                  <div className="px-3 py-2 text-xs text-muted-foreground">
                    No credentials yet. Create one instead.
                  </div>
                ) : null}
                {options.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name} — <span className="text-muted-foreground">{c.kind}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          );
        })()
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label>Kind</Label>
            <Input value={kindLabel} disabled />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-new-name`}>Name</Label>
            <Input
              id={`${idPrefix}-new-name`}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor={`${idPrefix}-new-value`}>Value</Label>
            <Textarea
              id={`${idPrefix}-new-value`}
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder={valuePlaceholder}
              rows={2}
            />
          </div>
        </div>
      )}
    </div>
  );
}
