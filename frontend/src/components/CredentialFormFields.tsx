import type {
  CredentialCreateInput,
  CredentialKind,
  CredentialRotateInput,
} from "@/api/types";
import { CREDENTIAL_KIND_LABELS } from "@/api/types";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/**
 * Local-first form state for building a CredentialCreateInput. Callers
 * store this object and pass it through `buildCredentialCreate()` on submit
 * to get a validated payload (or null when required fields are missing).
 *
 * Why one flat state instead of per-kind discriminated state? In practice
 * users switch kind mid-edit (they picked wrong, want basic auth instead)
 * and we want to preserve any overlapping fields (name stays). Flat ==
 * fewer surprises.
 */
export interface CredentialFormState {
  kind: CredentialKind;
  name: string;
  value: string; // used by https_token / jira_token / llm_api_key
  username: string; // https_basic
  password: string; // https_basic
  private_key: string; // ssh_key
  passphrase: string; // ssh_key
  known_hosts: string; // ssh_key
  expires_at: string; // ISO date string (YYYY-MM-DD) or empty string
}

export function emptyCredentialForm(kind: CredentialKind = "https_token"): CredentialFormState {
  return {
    kind,
    name: "",
    value: "",
    username: "",
    password: "",
    private_key: "",
    passphrase: "",
    known_hosts: "",
    expires_at: "",
  };
}

/** Derive a backend CredentialCreateInput from the form state. Returns
 *  null + validation messages when required fields are empty. */
export function buildCredentialCreate(
  state: CredentialFormState,
): { ok: true; input: CredentialCreateInput } | { ok: false; error: string } {
  const name = state.name.trim();
  if (!name) return { ok: false, error: "Name is required" };

  const expires_at = state.expires_at
    ? new Date(state.expires_at).toISOString()
    : undefined;

  switch (state.kind) {
    case "https_token":
    case "jira_token":
    case "llm_api_key": {
      const value = state.value.trim();
      if (!value) return { ok: false, error: "Value is required" };
      return { ok: true, input: { kind: state.kind, name, value, expires_at } };
    }
    case "https_basic": {
      const username = state.username.trim();
      const password = state.password;
      if (!username) return { ok: false, error: "Username is required" };
      if (!password) return { ok: false, error: "Password is required" };
      return {
        ok: true,
        input: { kind: "https_basic", name, username, password, expires_at },
      };
    }
    case "ssh_key": {
      const private_key = state.private_key.trim();
      if (!private_key) return { ok: false, error: "Private key is required" };
      return {
        ok: true,
        input: {
          kind: "ssh_key",
          name,
          private_key,
          passphrase: state.passphrase ? state.passphrase : null,
          known_hosts: state.known_hosts ? state.known_hosts : null,
          expires_at,
        },
      };
    }
  }
}

/** Same as buildCredentialCreate, but omits the name for the rotate flow. */
export function buildCredentialRotate(
  state: CredentialFormState,
): { ok: true; input: CredentialRotateInput } | { ok: false; error: string } {
  switch (state.kind) {
    case "https_token":
    case "jira_token":
    case "llm_api_key": {
      const value = state.value.trim();
      if (!value) return { ok: false, error: "Value is required" };
      return { ok: true, input: { kind: state.kind, value } };
    }
    case "https_basic": {
      const username = state.username.trim();
      const password = state.password;
      if (!username) return { ok: false, error: "Username is required" };
      if (!password) return { ok: false, error: "Password is required" };
      return { ok: true, input: { kind: "https_basic", username, password } };
    }
    case "ssh_key": {
      const private_key = state.private_key.trim();
      if (!private_key) return { ok: false, error: "Private key is required" };
      return {
        ok: true,
        input: {
          kind: "ssh_key",
          private_key,
          passphrase: state.passphrase ? state.passphrase : null,
          known_hosts: state.known_hosts ? state.known_hosts : null,
        },
      };
    }
  }
}

export interface CredentialFormFieldsProps {
  /** Prefix for html `id`s so multiple copies can coexist on a page. */
  idPrefix: string;
  state: CredentialFormState;
  onChange: (next: CredentialFormState) => void;
  /** Show the Kind selector + Name input. Off for rotate (kind locked,
   *  name already exists). */
  showKindAndName?: boolean;
  /** Limit the kinds exposed in the selector. Useful in the Settings page
   *  (Jira cred shouldn't offer ssh_key) and the RepoFormDialog
   *  (only git-auth kinds). */
  allowedKinds?: readonly CredentialKind[];
}

const DEFAULT_KINDS: CredentialKind[] = [
  "https_token",
  "https_basic",
  "ssh_key",
  "jira_token",
  "llm_api_key",
];

export function CredentialFormFields({
  idPrefix,
  state,
  onChange,
  showKindAndName = true,
  allowedKinds = DEFAULT_KINDS,
}: CredentialFormFieldsProps) {
  const patch = (p: Partial<CredentialFormState>) => onChange({ ...state, ...p });

  return (
    <div className="space-y-4">
      {showKindAndName ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-kind`}>Kind</Label>
            <Select
              value={state.kind}
              onValueChange={(v) => patch({ kind: v as CredentialKind })}
            >
              <SelectTrigger id={`${idPrefix}-kind`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {allowedKinds.map((k) => (
                  <SelectItem key={k} value={k}>
                    {CREDENTIAL_KIND_LABELS[k]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-name`}>Name</Label>
            <Input
              id={`${idPrefix}-name`}
              value={state.name}
              onChange={(e) => patch({ name: e.target.value })}
              placeholder="e.g. github-read-token"
            />
          </div>
        </div>
      ) : null}

      {state.kind === "https_basic" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-username`}>Username</Label>
            <Input
              id={`${idPrefix}-username`}
              value={state.username}
              onChange={(e) => patch({ username: e.target.value })}
              placeholder="alice"
              autoComplete="off"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-password`}>Password</Label>
            <Input
              id={`${idPrefix}-password`}
              type="password"
              value={state.password}
              onChange={(e) => patch({ password: e.target.value })}
              autoComplete="new-password"
            />
          </div>
        </div>
      ) : null}

      {state.kind === "ssh_key" ? (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor={`${idPrefix}-pk`}>Private key (PEM)</Label>
            <Textarea
              id={`${idPrefix}-pk`}
              value={state.private_key}
              onChange={(e) => patch({ private_key: e.target.value })}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;…&#10;-----END OPENSSH PRIVATE KEY-----"
              rows={6}
              className="font-mono text-xs"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor={`${idPrefix}-passphrase`}>Passphrase</Label>
              <Input
                id={`${idPrefix}-passphrase`}
                type="password"
                value={state.passphrase}
                onChange={(e) => patch({ passphrase: e.target.value })}
                placeholder="Leave blank if the key is unencrypted"
                autoComplete="new-password"
              />
              <p className="text-xs text-muted-foreground">
                Optional. Passphrase-protected keys aren't auto-unlocked yet (M3+).
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={`${idPrefix}-kh`}>Known hosts</Label>
              <Textarea
                id={`${idPrefix}-kh`}
                value={state.known_hosts}
                onChange={(e) => patch({ known_hosts: e.target.value })}
                placeholder="gitea.example.com ssh-ed25519 AAAA…"
                rows={2}
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Optional host-key pin. Leave blank to trust-on-first-use.
              </p>
            </div>
          </div>
        </div>
      ) : null}

      {state.kind === "https_token" ||
      state.kind === "jira_token" ||
      state.kind === "llm_api_key" ? (
        <div className="space-y-1.5">
          <Label htmlFor={`${idPrefix}-value`}>Value</Label>
          <Textarea
            id={`${idPrefix}-value`}
            value={state.value}
            onChange={(e) => patch({ value: e.target.value })}
            placeholder="Paste token. Encrypted at rest."
            rows={3}
            className="font-mono text-xs"
            autoComplete="off"
          />
        </div>
      ) : null}

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-expires`}>
          Expires <span className="text-muted-foreground font-normal">(optional)</span>
        </Label>
        <Input
          id={`${idPrefix}-expires`}
          type="date"
          value={state.expires_at}
          onChange={(e) => patch({ expires_at: e.target.value })}
          className="w-48"
        />
        <p className="text-xs text-muted-foreground">
          Set for rotation reminders. Leave blank for no expiry.
        </p>
      </div>
    </div>
  );
}
