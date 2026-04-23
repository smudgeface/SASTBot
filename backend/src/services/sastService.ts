import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { Prisma, PrismaClient, SastFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";

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
export async function runOpengrep(scopeDir: string): Promise<SarifDoc | null> {
  logger.info({ scopeDir }, "[sastService] running opengrep");
  try {
    const { stdout } = await execFileAsync(
      OPENGREP_BIN,
      ["scan", "--config", "auto", "--sarif", scopeDir],
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

      // Snippet: prefer region snippet, fall back to null
      const rawSnippet = loc?.region?.snippet?.text ?? null;
      const snippet = rawSnippet;
      const normalizedForHash = normalizeSnippet(rawSnippet ?? "");
      const fingerprint = computeFingerprint(ruleId, normalizedForHash);

      inputs.push({
        ruleId,
        ruleName: rule?.name ?? null,
        ruleMessage:
          result.message?.text ??
          rule?.shortDescription?.text ??
          rule?.fullDescription?.text ??
          null,
        cweIds: extractCweIds(result),
        severity: mapLevel(result.level),
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
// Triage inheritance
// ---------------------------------------------------------------------------

type Tx = PrismaClient | Prisma.TransactionClient;

/**
 * Check whether a previous scan in the same scope resolved this fingerprint.
 * Returns the inherited status + reason when the most recent match is
 * suppressed or false_positive; null otherwise.
 */
export async function inheritTriage(
  scopeId: string,
  fingerprint: string,
  client: Tx,
): Promise<{ status: string; reason: string | null } | null> {
  const prior = await (client as PrismaClient).sastFinding.findFirst({
    where: {
      scopeId,
      fingerprint,
      triageStatus: { in: ["suppressed", "false_positive"] },
    },
    orderBy: { createdAt: "desc" },
    select: { triageStatus: true, suppressedReason: true, triageReasoning: true },
  });
  if (!prior) return null;
  return {
    status: prior.triageStatus,
    reason: prior.suppressedReason ?? prior.triageReasoning ?? null,
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export async function persistSastFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  inputs: SastFindingInput[],
  client: Tx,
): Promise<SastFinding[]> {
  if (inputs.length === 0) return [];

  const rows: Prisma.SastFindingCreateManyInput[] = [];

  for (const input of inputs) {
    const inherited = await inheritTriage(scopeId, input.fingerprint, client);

    const row: Prisma.SastFindingCreateManyInput = {
      scanRunId,
      scopeId,
      orgId,
      fingerprint: input.fingerprint,
      ruleId: input.ruleId,
      ruleName: input.ruleName,
      ruleMessage: input.ruleMessage,
      cweIds: input.cweIds,
      severity: input.severity,
      filePath: input.filePath,
      startLine: input.startLine,
      endLine: input.endLine,
      snippet: input.snippet,
      triageStatus: inherited?.status ?? "pending",
      suppressedReason: inherited?.reason ?? null,
    };

    rows.push(row);
  }

  await (client as PrismaClient).sastFinding.createMany({
    data: rows,
    skipDuplicates: true, // [scanRunId, fingerprint] unique index
  });

  return (client as PrismaClient).sastFinding.findMany({
    where: { scanRunId },
    orderBy: { severity: "asc" },
  });
}
