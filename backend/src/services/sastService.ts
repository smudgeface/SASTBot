import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import type { Prisma, PrismaClient, SastFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import { upsertSastIssueFromDetection } from "./issueService.js";

const execFileAsync = promisify(execFile);
const logger = pino({ level: loadConfig().logLevel, name: "sastService" });

const OPENGREP_BIN = "/usr/local/bin/opengrep";
const OPENGREP_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

// ---------------------------------------------------------------------------
// SARIF 2.1.0 types (subset)
// ---------------------------------------------------------------------------

interface SarifPhysicalLocation {
  artifactLocation?: { uri?: string };
  region?: { startLine?: number; endLine?: number; snippet?: { text?: string } };
  // contextRegion provides surrounding lines (±N from the match) — preferred for display
  contextRegion?: { startLine?: number; endLine?: number; snippet?: { text?: string } };
}

interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
}

interface SarifTaxonReference {
  id?: string;
  toolComponent?: { name?: string };
}

interface SarifResult {
  ruleId?: string;
  level?: string; // "error" | "warning" | "note" | "none"
  message?: { text?: string };
  locations?: SarifLocation[];
  properties?: {
    cwe?: string | string[];
    [k: string]: unknown;
  };
  taxa?: SarifTaxonReference[];
}

interface SarifRule {
  id?: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  // Opengrep/Semgrep often omits result.level; fall back to defaultConfiguration
  defaultConfiguration?: { level?: string };
}

interface SarifToolDriver {
  rules?: SarifRule[];
}

interface SarifRun {
  tool?: { driver?: SarifToolDriver };
  results?: SarifResult[];
}

interface SarifDoc {
  runs?: SarifRun[];
}

// ---------------------------------------------------------------------------
// Internal input type
// ---------------------------------------------------------------------------

export interface SastFindingInput {
  ruleId: string;
  ruleName: string | null;
  ruleMessage: string | null;
  cweIds: string[];
  severity: string;
  filePath: string;
  startLine: number;
  endLine: number | null;
  snippet: string | null;
  fingerprint: string;
}

// ---------------------------------------------------------------------------
// Opengrep invocation
// ---------------------------------------------------------------------------

/**
 * Run Opengrep against scopeDir and return the parsed SARIF doc.
 * Returns null if the binary is missing (ENOENT) so the caller can
 * write a warning and continue with SCA-only results.
 */
export async function runOpengrep(scopeDir: string, excludes: string[] = []): Promise<SarifDoc | null> {
  // Opengrep's --exclude takes a path/glob and can be repeated. We pass each
  // sibling-scope subdir so the broader scope doesn't double-scan files that
  // the deeper scope already owns.
  const excludeArgs = excludes.flatMap((p) => ["--exclude", p]);
  logger.info({ scopeDir, excludes }, "[sastService] running opengrep");
  try {
    const { stdout } = await execFileAsync(
      OPENGREP_BIN,
      ["scan", "--config", "auto", "--sarif", ...excludeArgs, scopeDir],
      {
        timeout: OPENGREP_TIMEOUT_MS,
        maxBuffer: 64 * 1024 * 1024, // 64 MB — SARIF for large repos can be large
      },
    );
    return JSON.parse(stdout) as SarifDoc;
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") {
      logger.warn("[sastService] opengrep binary not found");
      return null;
    }
    // Opengrep exits with code 1 when findings are present; stdout still has the SARIF.
    const spawnErr = err as { stdout?: string; stderr?: string; code?: number };
    if (spawnErr.stdout && spawnErr.stdout.trim().startsWith("{")) {
      logger.info(
        { findings: "present" },
        "[sastService] opengrep exited non-zero (findings found) — parsing stdout",
      );
      return JSON.parse(spawnErr.stdout) as SarifDoc;
    }
    logger.error({ err }, "[sastService] opengrep failed");
    throw err;
  }
}

// ---------------------------------------------------------------------------
// SARIF parsing
// ---------------------------------------------------------------------------

function mapLevel(level: string | undefined): string {
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    default:
      return "info";
  }
}

function extractCweIds(result: SarifResult): string[] {
  const ids: string[] = [];
  // From properties.cwe (may be string or array)
  const cwe = result.properties?.cwe;
  if (typeof cwe === "string") {
    ids.push(cwe);
  } else if (Array.isArray(cwe)) {
    ids.push(...cwe.filter((c): c is string => typeof c === "string"));
  }
  // From taxa references (Semgrep/Opengrep style)
  for (const taxon of result.taxa ?? []) {
    if (taxon.id && taxon.toolComponent?.name?.toLowerCase() === "cwe") {
      ids.push(taxon.id);
    }
  }
  return [...new Set(ids)];
}

export function normalizeSnippet(snippet: string): string {
  return snippet.trim().replace(/\s+/g, " ");
}

export function computeFingerprint(ruleId: string, normalizedSnippet: string): string {
  return createHash("sha256")
    .update(`${ruleId}:${normalizedSnippet}`)
    .digest("hex")
    .slice(0, 16);
}

export function parseSarif(doc: SarifDoc, scopeDir?: string): SastFindingInput[] {
  const inputs: SastFindingInput[] = [];
  // Normalize scopeDir: strip trailing slash, add leading / if needed
  const base = scopeDir ? scopeDir.replace(/\/$/, "") : "";

  for (const run of doc.runs ?? []) {
    // Build a rule-id → rule metadata map for this run
    const ruleMap = new Map<string, SarifRule>();
    for (const rule of run.tool?.driver?.rules ?? []) {
      if (rule.id) ruleMap.set(rule.id, rule);
    }

    for (const result of run.results ?? []) {
      const ruleId = result.ruleId ?? "unknown";
      const rule = ruleMap.get(ruleId);
      const loc = result.locations?.[0]?.physicalLocation;

      // Strip file:// prefix and make path relative to scopeDir
      const rawUri = loc?.artifactLocation?.uri ?? "";
      const absPath = rawUri.replace(/^file:\/\//, "");
      let filePath: string;
      if (base && absPath.startsWith(base)) {
        filePath = absPath.slice(base.length).replace(/^\/+/, "");
      } else {
        filePath = absPath.replace(/^\/+/, "") || rawUri;
      }

      const startLine = loc?.region?.startLine ?? 1;
      const endLine = loc?.region?.endLine ?? null;

      // For the fingerprint hash use only the exact match region (stable across context changes).
      // For display prefer contextRegion which gives surrounding lines (±N); fall back to region.
      const matchSnippet = loc?.region?.snippet?.text ?? null;
      const contextSnippet = loc?.contextRegion?.snippet?.text ?? null;
      const snippet = contextSnippet ?? matchSnippet;
      const normalizedForHash = normalizeSnippet(matchSnippet ?? "");
      const fingerprint = computeFingerprint(ruleId, normalizedForHash);

      // Opengrep often omits result.level for INFO/WARNING rules;
      // fall back to the rule's defaultConfiguration.level.
      const effectiveLevel = result.level ?? rule?.defaultConfiguration?.level;

      inputs.push({
        ruleId,
        ruleName: rule?.name ?? null,
        ruleMessage:
          result.message?.text ??
          rule?.shortDescription?.text ??
          rule?.fullDescription?.text ??
          null,
        cweIds: extractCweIds(result),
        severity: mapLevel(effectiveLevel),
        filePath,
        startLine,
        endLine: endLine !== startLine ? endLine : null,
        snippet,
        fingerprint,
      });
    }
  }

  return inputs;
}

// ---------------------------------------------------------------------------
// Context snippet (±N lines around the match)
// ---------------------------------------------------------------------------

const CONTEXT_LINES = 3;

/**
 * Read the file at `absPath` and return `CONTEXT_LINES` lines before and after
 * `startLine` (1-indexed). Returns null if the file cannot be read.
 */
async function readContextSnippet(absPath: string, startLine: number): Promise<string | null> {
  try {
    const content = await readFile(absPath, "utf8");
    const lines = content.split("\n");
    const from = Math.max(0, startLine - 1 - CONTEXT_LINES);       // 0-indexed
    const to = Math.min(lines.length, startLine - 1 + CONTEXT_LINES + 1);
    return lines.slice(from, to).join("\n");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

type Tx = PrismaClient | Prisma.TransactionClient;

/**
 * Upsert a SastIssue for each detection, then create the SastFinding detection
 * row linking back to the issue. Returns the inserted SastFinding rows.
 */
export async function persistSastFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  inputs: SastFindingInput[],
  client: Tx,
  scopeDir?: string, // when provided, read ±3 lines of context from the file
): Promise<SastFinding[]> {
  if (inputs.length === 0) return [];

  for (const input of inputs) {
    // Enrich snippet with surrounding context lines if we have the source tree
    let snippet = input.snippet;
    if (scopeDir && input.filePath) {
      const absPath = join(scopeDir, input.filePath);
      const ctx = await readContextSnippet(absPath, input.startLine);
      if (ctx) snippet = ctx;
    }

    const { issue } = await upsertSastIssueFromDetection(client, scanRunId, scopeId, orgId, {
      fingerprint: input.fingerprint,
      ruleId: input.ruleId,
      ruleName: input.ruleName,
      ruleMessage: input.ruleMessage,
      severity: input.severity,
      cweIds: input.cweIds,
      filePath: input.filePath,
      startLine: input.startLine,
      snippet,
    });

    // [scanRunId, fingerprint] unique index skips duplicates across retried scans
    await (client as PrismaClient).sastFinding.upsert({
      where: { scanRunId_fingerprint: { scanRunId, fingerprint: input.fingerprint } },
      create: {
        scanRunId,
        scopeId,
        orgId,
        issueId: issue.id,
        fingerprint: input.fingerprint,
        ruleId: input.ruleId,
        ruleName: input.ruleName,
        ruleMessage: input.ruleMessage,
        cweIds: input.cweIds,
        severity: input.severity,
        filePath: input.filePath,
        startLine: input.startLine,
        endLine: input.endLine,
        snippet,
      },
      update: {},
    });
  }

  return (client as PrismaClient).sastFinding.findMany({
    where: { scanRunId },
    orderBy: { severity: "asc" },
  });
}

// ---------------------------------------------------------------------------
// One-shot backfill: re-read ±N lines of context for existing SAST issues
// that were persisted before the context logic was added (their snippet has
// no newlines). Only works for repos with retained clones.
// ---------------------------------------------------------------------------

export async function backfillSastContextSnippets(db: PrismaClient): Promise<void> {
  const { repoCachePath } = await import("./repoCache.js");

  const rows = await db.sastIssue.findMany({
    where: {
      latestSnippet: { not: null },
      // Heuristic: single-line snippets (no \n) are missing context.
      NOT: { latestSnippet: { contains: "\n" } },
    },
    select: {
      id: true, latestFilePath: true, latestStartLine: true, scopeId: true,
    },
  });
  if (rows.length === 0) return;

  // Cache scope → (repoId, path) lookups to avoid N+1 queries.
  const scopeCache = new Map<string, { repoId: string; path: string }>();
  async function getScope(scopeId: string) {
    let hit = scopeCache.get(scopeId);
    if (hit) return hit;
    const s = await db.scanScope.findUnique({ where: { id: scopeId }, select: { repoId: true, path: true } });
    if (!s) return null;
    hit = { repoId: s.repoId, path: s.path };
    scopeCache.set(scopeId, hit);
    return hit;
  }

  let updated = 0;
  for (const row of rows) {
    const scope = await getScope(row.scopeId);
    if (!scope) continue;
    const cacheDir = repoCachePath(scope.repoId);
    const scanDir = scope.path === "/" || scope.path === "" ? cacheDir : join(cacheDir, scope.path);
    const absPath = join(scanDir, row.latestFilePath);
    const ctx = await readContextSnippet(absPath, row.latestStartLine);
    if (!ctx) continue;
    await db.sastIssue.update({ where: { id: row.id }, data: { latestSnippet: ctx } });
    updated++;
  }
  if (updated > 0) logger.info({ updated, total: rows.length }, "[sastService] backfilled SAST context snippets");
}
