/**
 * Jira Cloud REST API v3 client (read-only).
 *
 * Auth: Basic base64(email:apiToken) — NOT base64(apiToken).
 * All methods throw on network failure; callers decide how to surface errors.
 */
import { pino } from "pino";

import { loadConfig } from "../config.js";
import { decodeCredential } from "./credentialService.js";
import { getOrCreateSettings } from "./settingsService.js";

const logger = pino({ level: loadConfig().logLevel, name: "jiraClient" });

const TIMEOUT_MS = 10_000;
const MAX_BATCH = 50; // Jira JQL IN clause practical limit

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface JiraConfig {
  baseUrl: string;   // https://acme.atlassian.net (no trailing slash)
  email: string;
  apiToken: string;
}

/** Load Jira config from AppSettings + Credential for the given org. */
export async function loadJiraConfig(orgId: string | null): Promise<JiraConfig | null> {
  const settings = await getOrCreateSettings(orgId);
  if (!settings.jiraBaseUrl || !settings.jiraEmail || !settings.jiraCredentialId) {
    return null;
  }
  try {
    const cred = await decodeCredential(settings.jiraCredentialId);
    if (cred.kind !== "jira_token") {
      logger.warn("[jiraClient] credential is not jira_token kind");
      return null;
    }
    return {
      baseUrl: settings.jiraBaseUrl.replace(/\/$/, ""),
      email: settings.jiraEmail,
      apiToken: cred.value,
    };
  } catch {
    logger.warn("[jiraClient] failed to decode Jira credential");
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function authHeader(cfg: JiraConfig): string {
  return "Basic " + Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString("base64");
}

async function jiraFetch<T>(cfg: JiraConfig, path: string): Promise<T> {
  const url = `${cfg.baseUrl}/rest/api/3${path}`;
  const res = await fetch(url, {
    headers: {
      Authorization: authHeader(cfg),
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Jira API ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Ticket metadata
// ---------------------------------------------------------------------------

export interface JiraTicketMeta {
  issueId: string;
  issueKey: string;
  projectKey: string | null;
  projectName: string | null;
  summary: string | null;
  status: string | null;
  statusCategory: "new" | "indeterminate" | "done" | null;
  resolution: string | null;          // raw resolution name; null if unresolved
  assigneeName: string | null;
  assigneeEmail: string | null;
  fixVersions: string[];
  issueType: string | null;
  resolvedAt: Date | null;
  url: string;
}

interface JiraIssueResponse {
  id: string;
  key: string;
  fields: {
    summary?: string | null;
    status?: {
      name?: string | null;
      statusCategory?: { key?: string | null } | null;
    } | null;
    resolution?: { name?: string | null } | null;
    assignee?: { displayName?: string | null; emailAddress?: string | null } | null;
    fixVersions?: Array<{ name?: string | null }>;
    issuetype?: { name?: string | null } | null;
    resolutiondate?: string | null;
    project?: { key?: string | null; name?: string | null } | null;
  };
  self?: string;
}

function mapStatusCategory(key: string | null | undefined): JiraTicketMeta["statusCategory"] {
  if (key === "new") return "new";
  if (key === "indeterminate") return "indeterminate";
  if (key === "done") return "done";
  return null;
}

function issueToMeta(issue: JiraIssueResponse, baseUrl: string): JiraTicketMeta {
  const f = issue.fields ?? {};
  return {
    issueId: issue.id,
    issueKey: issue.key,
    projectKey: f.project?.key ?? null,
    projectName: f.project?.name ?? null,
    summary: f.summary ?? null,
    status: f.status?.name ?? null,
    statusCategory: mapStatusCategory(f.status?.statusCategory?.key),
    resolution: f.resolution?.name ?? null,
    assigneeName: f.assignee?.displayName ?? null,
    assigneeEmail: f.assignee?.emailAddress ?? null,
    fixVersions: (f.fixVersions ?? []).map((v) => v.name ?? "").filter(Boolean),
    issueType: f.issuetype?.name ?? null,
    resolvedAt: f.resolutiondate ? new Date(f.resolutiondate) : null,
    url: `${baseUrl}/browse/${issue.key}`,
  };
}

const FIELDS = "summary,status,resolution,assignee,fixVersions,issuetype,resolutiondate,project";

/** Fetch a single ticket by key. Throws on error. */
export async function fetchTicket(cfg: JiraConfig, issueKey: string): Promise<JiraTicketMeta> {
  const issue = await jiraFetch<JiraIssueResponse>(cfg, `/issue/${issueKey}?fields=${FIELDS}`);
  return issueToMeta(issue, cfg.baseUrl);
}

/** Fetch multiple tickets by key via JQL. Missing keys are returned with syncError set.
 *  Results keyed by issueKey. */
export async function fetchTicketsBatch(
  cfg: JiraConfig,
  issueKeys: string[],
): Promise<Map<string, JiraTicketMeta | { error: string }>> {
  const result = new Map<string, JiraTicketMeta | { error: string }>();
  if (issueKeys.length === 0) return result;

  for (let i = 0; i < issueKeys.length; i += MAX_BATCH) {
    const chunk = issueKeys.slice(i, i + MAX_BATCH);
    const jql = `key in (${chunk.join(",")})`;

    interface SearchResponse {
      issues: JiraIssueResponse[];
    }

    const data = await jiraFetch<SearchResponse>(
      cfg,
      `/search?jql=${encodeURIComponent(jql)}&fields=${FIELDS}&maxResults=${MAX_BATCH}`,
    );

    const found = new Set<string>();
    for (const issue of data.issues ?? []) {
      const meta = issueToMeta(issue, cfg.baseUrl);
      result.set(meta.issueKey, meta);
      found.add(meta.issueKey);
    }
    // Mark any keys not returned by Jira as not-found
    for (const key of chunk) {
      if (!found.has(key)) {
        result.set(key, { error: "Ticket not found or inaccessible" });
      }
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Connection check
// ---------------------------------------------------------------------------

export type JiraConnectionResult =
  | { ok: true; accountName: string; accountEmail: string }
  | { ok: false; error: string };

export async function checkJiraConnection(cfg: JiraConfig): Promise<JiraConnectionResult> {
  try {
    const me = await jiraFetch<{ displayName?: string; emailAddress?: string }>(cfg, "/myself");
    return {
      ok: true,
      accountName: me.displayName ?? cfg.email,
      accountEmail: me.emailAddress ?? cfg.email,
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// ---------------------------------------------------------------------------
// Resolutions
// ---------------------------------------------------------------------------

export interface JiraResolution {
  id: string;
  name: string;
  description: string | null;
}

/** Fetch the org's configured resolution values. */
export async function fetchResolutions(cfg: JiraConfig): Promise<JiraResolution[]> {
  const data = await jiraFetch<Array<{ id?: string; name?: string; description?: string }>>(
    cfg,
    "/resolution",
  );
  return data
    .filter((r) => r.id && r.name)
    .map((r) => ({ id: r.id!, name: r.name!, description: r.description ?? null }));
}

// ---------------------------------------------------------------------------
// Issue key validation
// ---------------------------------------------------------------------------

/** e.g. "SEC-123", "GOS-4567" */
export function isValidIssueKey(key: string): boolean {
  return /^[A-Z][A-Z0-9]+-\d+$/.test(key);
}
