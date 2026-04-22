import { useEffect, useState } from "react";

import { useCredentials } from "@/api/queries/credentials";
import { useSettings, useUpdateSettings } from "@/api/queries/settings";
import type { AdminSettingsUpdate, LlmApiFormat } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

const LLM_DEFAULTS = {
  base_url: "https://api.ai.mytkhgroup.com",
  api_format: "anthropic-messages" as LlmApiFormat,
  model: "claude-opus-4-7",
};

type CredentialChoice = "existing" | "new";

export default function SettingsPage() {
  const settings = useSettings();
  const credentials = useCredentials();
  const updateSettings = useUpdateSettings();
  const { toast } = useToast();

  // Jira section state
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraCredChoice, setJiraCredChoice] = useState<CredentialChoice>("existing");
  const [jiraCredId, setJiraCredId] = useState<string>("");
  const [jiraNewName, setJiraNewName] = useState("");
  const [jiraNewValue, setJiraNewValue] = useState("");

  // LLM section state
  const [llmBaseUrl, setLlmBaseUrl] = useState(LLM_DEFAULTS.base_url);
  const [llmApiFormat, setLlmApiFormat] = useState<LlmApiFormat>(LLM_DEFAULTS.api_format);
  const [llmModel, setLlmModel] = useState(LLM_DEFAULTS.model);
  const [llmCredChoice, setLlmCredChoice] = useState<CredentialChoice>("existing");
  const [llmCredId, setLlmCredId] = useState<string>("");
  const [llmNewName, setLlmNewName] = useState("");
  const [llmNewValue, setLlmNewValue] = useState("");

  // When the settings query completes, hydrate the form.
  useEffect(() => {
    const data = settings.data;
    if (!data) return;
    setJiraBaseUrl(data.jira_base_url ?? "");
    setJiraCredId(data.jira_credential_id ?? "");
    setJiraCredChoice(data.jira_credential_id ? "existing" : "new");

    setLlmBaseUrl(data.llm_base_url || LLM_DEFAULTS.base_url);
    setLlmApiFormat((data.llm_api_format as LlmApiFormat) || LLM_DEFAULTS.api_format);
    setLlmModel(data.llm_model || LLM_DEFAULTS.model);
    setLlmCredId(data.llm_credential_id ?? "");
    setLlmCredChoice(data.llm_credential_id ? "existing" : "new");
  }, [settings.data]);

  const jiraOptions = credentials.data?.filter((c) => c.kind.startsWith("jira")) ?? [];
  const llmOptions = credentials.data?.filter((c) => c.kind === "llm_api_key") ?? [];

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

  const onSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: AdminSettingsUpdate = {
      jira_base_url: jiraBaseUrl.trim() || null,
      jira_credential_id: jiraCredChoice === "existing" ? jiraCredId || null : null,
      jira_credential: buildJiraCred(),
      llm_base_url: llmBaseUrl.trim() || null,
      llm_api_format: llmApiFormat,
      llm_model: llmModel.trim() || null,
      llm_credential_id: llmCredChoice === "existing" ? llmCredId || null : null,
      llm_credential: buildLlmCred(),
    };

    try {
      await updateSettings.mutateAsync(payload);
      toast({ title: "Settings saved" });
      // Clear fresh credential fields after save to avoid re-submitting.
      setJiraNewName("");
      setJiraNewValue("");
      setLlmNewName("");
      setLlmNewValue("");
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to save settings",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
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
            <div className="space-y-1.5">
              <Label htmlFor="jira-url">Base URL</Label>
              <Input
                id="jira-url"
                value={jiraBaseUrl}
                onChange={(e) => setJiraBaseUrl(e.target.value)}
                placeholder="https://yourorg.atlassian.net"
              />
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
            />
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
            />
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button type="submit" disabled={updateSettings.isPending}>
            {updateSettings.isPending ? "Saving…" : "Save settings"}
          </Button>
        </div>
      </form>
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
        <Select value={credentialId} onValueChange={setCredentialId}>
          <SelectTrigger>
            <SelectValue placeholder="Select a credential" />
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
