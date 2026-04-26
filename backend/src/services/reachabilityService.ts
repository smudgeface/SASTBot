/**
 * SCA reachability analysis — M5 refactor.
 *
 * Queries ScaIssue rows detected in the current scan and writes reachability
 * verdicts back to the issue (not the detection rows). The ripgrep + LLM
 * confirmation logic is unchanged.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { Prisma, PrismaClient, ScaIssue } from "@prisma/client";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { callLlm, parseJsonResponse } from "./llmClient.js";
import { getOrCreateSettings } from "./settingsService.js";
import { getOrExtract } from "./cveKnowledgeService.js";
import type { OsvVulnForExtraction } from "./cveKnowledgeService.js";

const execFileAsync = promisify(execFile);
const logger = pino({ level: loadConfig().logLevel, name: "reachabilityService" });

type Tx = PrismaClient | Prisma.TransactionClient;

// Severity ladder, highest to lowest. info/unknown intentionally excluded —
// they are too noisy to act on and don't appear in the user-facing dropdown.
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
function severitiesAtLeast(min: string): string[] {
  const minRank = SEVERITY_RANK[min] ?? SEVERITY_RANK.high;
  return Object.entries(SEVERITY_RANK)
    .filter(([, r]) => r >= minRank)
    .map(([s]) => s);
}

// ---------------------------------------------------------------------------
// Ripgrep
// ---------------------------------------------------------------------------

interface GrepHit {
  file: string;
  line: number;
  text: string;
}

async function ripgrepForFunction(
  functionName: string,
  scopeDir: string,
  maxCount = 20,
): Promise<GrepHit[]> {
  try {
    const { stdout } = await execFileAsync(
      "rg",
      [
        "--fixed-strings",
        "--line-number",
        "--max-count", String(maxCount),
        "--glob", "!node_modules",
        "--glob", "!.git",
        "--glob", "!dist",
        "--glob", "!build",
        "--glob", "!*.lock",
        "--glob", "!package-lock.json",
        "--glob", "!yarn.lock",
        "--glob", "!pnpm-lock.yaml",
        "--glob", "!Cargo.lock",
        "--glob", "!Gemfile.lock",
        "--glob", "!composer.lock",
        functionName,
        scopeDir,
      ],
      { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
    );

    return stdout
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const m = line.match(/^(.+):(\d+):(.*)$/);
        if (!m) return null;
        // Strip the absolute scope-working-dir prefix so paths shown to the
        // LLM (and persisted as call_sites) are relative to the repo root.
        let file = m[1]!;
        if (file.startsWith(scopeDir + "/")) file = file.slice(scopeDir.length + 1);
        return { file, line: parseInt(m[2], 10), text: m[3] };
      })
      .filter((h): h is GrepHit => h !== null);
  } catch (err) {
    const e = err as { code?: string | number };
    if (e.code === 1) return [];
    logger.warn({ functionName, err }, "[reachabilityService] ripgrep error");
    return [];
  }
}

// ---------------------------------------------------------------------------
// LLM confirmation
// ---------------------------------------------------------------------------

const CallSiteSchema = z.object({
  file: z.string(),
  line: z.number().int(),
  snippet: z.string(),
});
export type CallSite = z.infer<typeof CallSiteSchema>;

const ReachabilityResponseSchema = z.object({
  reachable: z.boolean(),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
  call_sites: z.array(CallSiteSchema).default([]),
});

const REACHABILITY_TOOL_SCHEMA = {
  type: "object",
  properties: {
    reachable: {
      type: "boolean",
      description: "true if the code appears to call the vulnerable function in a way that could trigger the vulnerability",
    },
    confidence: { type: "number", description: "0.0–1.0 confidence in your verdict" },
    reasoning: { type: "string", description: "One short paragraph explaining the verdict, naming the relevant call sites" },
    call_sites: {
      type: "array",
      description: "When reachable=true: the specific call sites that triggered the verdict, copied verbatim from the references above. Empty array when not reachable or no specific site applies.",
      items: {
        type: "object",
        properties: {
          file: { type: "string", description: "Path as shown in the references" },
          line: { type: "integer", description: "Line number as shown" },
          snippet: { type: "string", description: "The code line itself" },
        },
        required: ["file", "line", "snippet"],
      },
    },
  },
  required: ["reachable", "confidence", "reasoning", "call_sites"],
};

async function confirmReachabilityWithLlm(
  issue: ScaIssue,
  functionName: string,
  hits: GrepHit[],
  orgId: string | null,
): Promise<{ reachable: boolean; confidence: number; reasoning: string; callSites: CallSite[]; model: string } | null> {
  const sites = hits.slice(0, 3).map((h) => {
    return `File: ${h.file} line ${h.line}\n${h.text.trim()}`;
  });

  const prompt = `You are a security researcher assessing whether application code calls a vulnerable library function.

## Vulnerability
Package: ${issue.packageName}@${issue.latestPackageVersion ?? "unknown"}
CVE: ${issue.latestCveId ?? issue.osvId}
Summary: ${issue.latestSummary ?? "no summary"}
Vulnerable function: ${functionName}

## Code references found by grep
${sites.join("\n\n---\n\n")}

## Task
Does this code appear to call \`${functionName}\` in a way that could trigger the vulnerability?
Consider: is the function called with user-controlled input? Is the usage in a vulnerable code path?

If the vulnerability IS reachable, list the specific call_sites (file/line/snippet) you based the verdict on.
If it is NOT reachable, return call_sites=[] and explain why in the reasoning (e.g., the matches are unrelated, in dead code, or the input is constant).`;

  const result = await callLlm(
    { orgId, prompt, maxTokens: 512, toolName: "submit_reachability", toolSchema: REACHABILITY_TOOL_SCHEMA },
  );

  if (!result) return null;

  const parsed = parseJsonResponse(result.text, ReachabilityResponseSchema);
  if (!parsed) {
    logger.warn({ issueId: issue.id }, "[reachabilityService] LLM returned unparseable response");
    return null;
  }

  return {
    reachable: parsed.reachable,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
    callSites: parsed.call_sites ?? [],
    model: result.model,
  };
}

// ---------------------------------------------------------------------------
// Per-issue assessment (shared by scan-time and backfill paths)
// ---------------------------------------------------------------------------

async function assessOneIssue(
  issue: ScaIssue,
  scopeWorkingDir: string,
  orgId: string | null,
  db: PrismaClient,
): Promise<void> {
  // Already marked reachable (e.g. via SAST triage hints) AND we already have
  // structured confidence/call_sites data — skip LLM. If confidence is null
  // the row predates the schema and we want to re-run to populate it.
  if (issue.confirmedReachable && issue.reachableConfidence !== null) return;

  const osvVuln: OsvVulnForExtraction = {
    id: issue.osvId,
    cveId: issue.latestCveId,
    ecosystem: issue.latestEcosystem ?? "npm",
    packageName: issue.packageName,
    summary: issue.latestSummary,
    details: null,
    modified: null,
  };

  const knowledge = await getOrExtract(osvVuln, orgId, db);

  if (knowledge.vulnerableFunctions.length === 0) {
    await db.scaIssue.update({
      where: { id: issue.id },
      data: {
        reachableAssessedAt: new Date(),
        reachableReasoning: "No specific vulnerable functions identified from advisory",
      },
    });
    return;
  }

  let allHits: GrepHit[] = [];
  let matchedFunction = "";
  for (const fn of knowledge.vulnerableFunctions) {
    const hits = await ripgrepForFunction(fn, scopeWorkingDir);
    if (hits.length > 0) {
      allHits = hits;
      matchedFunction = fn;
      break;
    }
  }

  if (allHits.length === 0) {
    logger.info(
      { issueId: issue.id, functions: knowledge.vulnerableFunctions },
      "[reachabilityService] no references found — marking not reachable",
    );
    await db.scaIssue.update({
      where: { id: issue.id },
      data: {
        confirmedReachable: false,
        reachableReasoning: `No references to ${knowledge.vulnerableFunctions.join(", ")} found in scope`,
        reachableAssessedAt: new Date(),
      },
    });
    return;
  }

  logger.info(
    { issueId: issue.id, matchedFunction, hits: allHits.length },
    "[reachabilityService] hits found — asking LLM to confirm",
  );

  const confirmation = await confirmReachabilityWithLlm(issue, matchedFunction, allHits, orgId);

  if (!confirmation) {
    await db.scaIssue.update({
      where: { id: issue.id },
      data: {
        reachableAssessedAt: new Date(),
        reachableReasoning: `References to '${matchedFunction}' found in scope but LLM confirmation unavailable`,
      },
    });
    return;
  }

  await db.scaIssue.update({
    where: { id: issue.id },
    data: {
      confirmedReachable: confirmation.reachable,
      reachableReasoning: confirmation.reasoning,
      reachableConfidence: confirmation.confidence,
      reachableCallSites: confirmation.callSites.length > 0 ? confirmation.callSites : undefined,
      reachableAssessedAt: new Date(),
      reachableModel: confirmation.model,
    },
  });

  logger.info(
    { issueId: issue.id, reachable: confirmation.reachable, confidence: confirmation.confidence, sites: confirmation.callSites.length },
    "[reachabilityService] reachability assessed",
  );
}

// ---------------------------------------------------------------------------
// Main entrypoint
// ---------------------------------------------------------------------------

export async function assessReachability(
  scanRunId: string,
  scopeId: string,
  scopeWorkingDir: string,
  orgId: string | null,
  client: Tx,
): Promise<void> {
  const db = client as PrismaClient;
  const settings = await getOrCreateSettings(orgId);

  const minSeverity = settings.reachabilityMinSeverity;
  const allowedSeverities = severitiesAtLeast(minSeverity);

  // Query ScaIssue rows detected in this scan whose severity meets the gate.
  const issues = await db.scaIssue.findMany({
    where: {
      scopeId,
      lastSeenScanRunId: scanRunId,
      latestFindingType: "cve",
      latestSeverity: { in: allowedSeverities },
    },
  });

  if (issues.length === 0) {
    logger.info("[reachabilityService] no issues to assess");
    return;
  }

  logger.info(
    { count: issues.length, minSeverity },
    "[reachabilityService] assessing reachability",
  );

  for (const issue of issues) {
    await assessOneIssue(issue, scopeWorkingDir, orgId, db);
  }

  // Update scan-level counter from ScaIssue
  const reachableCount = await db.scaIssue.count({
    where: { scopeId, lastSeenScanRunId: scanRunId, confirmedReachable: true },
  });
  await db.scanRun.update({
    where: { id: scanRunId },
    data: { confirmedReachableCount: reachableCount },
  });
}

// ---------------------------------------------------------------------------
// Worker-startup backfill
//
// Assesses any ScaIssue that hasn't been assessed yet (reachable_assessed_at
// IS NULL) whose severity meets the configured gate. Only works for repos
// with retainClone=true — non-retained scans don't have a working tree on
// disk after the scan finishes. Idempotent: assessed rows drop out of the
// where filter, so re-runs are no-ops.
// ---------------------------------------------------------------------------

export async function backfillReachability(db: PrismaClient): Promise<void> {
  const { repoCachePath } = await import("./repoCache.js");
  const { join } = await import("node:path");
  const { stat } = await import("node:fs/promises");

  // We don't have org context at startup; assume single-org and load org=null.
  const settings = await getOrCreateSettings(null);
  const allowedSeverities = severitiesAtLeast(settings.reachabilityMinSeverity);

  // Two cohorts: never assessed, and assessed before we started capturing
  // confidence/call_sites. Re-running for both is safe and idempotent.
  const issues = await db.scaIssue.findMany({
    where: {
      latestFindingType: "cve",
      latestSeverity: { in: allowedSeverities },
      OR: [
        { reachableAssessedAt: null },
        { reachableAssessedAt: { not: null }, reachableConfidence: null },
      ],
    },
    select: { id: true, scopeId: true },
  });
  if (issues.length === 0) return;

  // Cache scope → working dir lookups; skip scopes whose repo isn't retained.
  type ScopeCache = { workingDir: string | null };
  const scopeCache = new Map<string, ScopeCache>();
  async function resolveScope(scopeId: string): Promise<string | null> {
    let cached = scopeCache.get(scopeId);
    if (cached) return cached.workingDir;
    const scope = await db.scanScope.findUnique({
      where: { id: scopeId },
      select: { repoId: true, path: true, repo: { select: { retainClone: true } } },
    });
    if (!scope || !scope.repo?.retainClone) {
      scopeCache.set(scopeId, { workingDir: null });
      return null;
    }
    const cacheDir = repoCachePath(scope.repoId);
    try {
      await stat(cacheDir);
    } catch {
      scopeCache.set(scopeId, { workingDir: null });
      return null;
    }
    const workingDir = scope.path === "/" || scope.path === "" ? cacheDir : join(cacheDir, scope.path);
    cached = { workingDir };
    scopeCache.set(scopeId, cached);
    return workingDir;
  }

  let assessed = 0;
  let skipped = 0;
  logger.info({ candidates: issues.length }, "[reachabilityService] backfill starting");
  for (const stub of issues) {
    const workingDir = await resolveScope(stub.scopeId);
    if (!workingDir) { skipped++; continue; }
    // Re-fetch with full row so assessOneIssue has all fields.
    const issue = await db.scaIssue.findUnique({ where: { id: stub.id } });
    if (!issue) continue;
    // Find the orgId for this issue's scope to pick up the right credentials.
    const scope = await db.scanScope.findUnique({ where: { id: stub.scopeId }, select: { orgId: true } });
    await assessOneIssue(issue, workingDir, scope?.orgId ?? null, db);
    assessed++;
  }
  logger.info({ assessed, skipped, total: issues.length }, "[reachabilityService] backfill complete");
}
