/**
 * SCA reachability analysis.
 *
 * For each high/critical SCA finding in a scan:
 *   1. Look up (or extract) the vulnerable function names via CveKnowledgeService.
 *   2. Ripgrep the scope directory for those function names.
 *   3. Zero hits → mark reachable=false (no LLM call needed — high confidence).
 *   4. Hits → ask LLM to confirm whether the code actually invokes the
 *      vulnerable functionality, with ±10 lines of context per match site.
 *
 * Also applies SAST-originated reachability hints: findings already marked
 * reachable via SAST triage (confirmed_reachable_sca_ids) are accepted as-is.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { Prisma, PrismaClient, ScanFinding } from "@prisma/client";
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
        // rg output: filepath:linenum:text
        const m = line.match(/^(.+):(\d+):(.*)$/);
        if (!m) return null;
        return { file: m[1], line: parseInt(m[2], 10), text: m[3] };
      })
      .filter((h): h is GrepHit => h !== null);
  } catch (err) {
    const e = err as { code?: string | number };
    // Exit code 1 = no matches (not an error)
    if (e.code === 1) return [];
    logger.warn({ functionName, err }, "[reachabilityService] ripgrep error");
    return [];
  }
}

// ---------------------------------------------------------------------------
// LLM reachability confirmation
// ---------------------------------------------------------------------------

const ReachabilityResponseSchema = z.object({
  reachable: z.boolean(),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
});

const REACHABILITY_TOOL_SCHEMA = {
  type: "object",
  properties: {
    reachable: {
      type: "boolean",
      description: "true if the code appears to call the vulnerable function in a way that could trigger the vulnerability",
    },
    confidence: { type: "number", description: "0.0–1.0 confidence" },
    reasoning: { type: "string", description: "One sentence explanation" },
  },
  required: ["reachable", "confidence", "reasoning"],
};

async function confirmReachabilityWithLlm(
  finding: ScanFinding & { component: { name: string; version: string | null } },
  functionName: string,
  hits: GrepHit[],
  orgId: string | null,
): Promise<{ reachable: boolean; confidence: number; reasoning: string; model: string } | null> {
  // Show up to 3 hit sites, each with surrounding context lines
  const sites = hits.slice(0, 3).map((h) => {
    return `File: ${h.file} line ${h.line}\n${h.text.trim()}`;
  });

  const prompt = `You are a security researcher assessing whether application code calls a vulnerable library function.

## Vulnerability
Package: ${finding.component.name}@${finding.component.version ?? "unknown"}
CVE: ${finding.cveId ?? finding.osvId}
Summary: ${finding.summary ?? "no summary"}
Vulnerable function: ${functionName}

## Code references found by grep
${sites.join("\n\n---\n\n")}

## Task
Does this code appear to call \`${functionName}\` in a way that could trigger the vulnerability?
Consider: is the function called with user-controlled input? Is the usage in a vulnerable code path?

Respond with whether the vulnerability appears reachable from this codebase.`;

  const result = await callLlm(
    {
      orgId,
      prompt,
      maxTokens: 256,
      toolName: "submit_reachability",
      toolSchema: REACHABILITY_TOOL_SCHEMA,
    },
    { skipEnabledCheck: false }, // respects the enabled toggle
  );

  if (!result) return null;

  const parsed = parseJsonResponse(result.text, ReachabilityResponseSchema);
  if (!parsed) {
    logger.warn({ findingId: finding.id }, "[reachabilityService] LLM returned unparseable response");
    return null;
  }

  return {
    reachable: parsed.reachable,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
    model: result.model,
  };
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

  if (!settings.llmAssistanceEnabled) {
    logger.info("[reachabilityService] LLM not enabled — skipping reachability");
    return;
  }

  const threshold = settings.reachabilityCvssThreshold;

  // Load high/critical SCA CVE findings not yet assessed.
  // Use cvssScore when available; fall back to severity string for advisories
  // that don't include a numeric CVSS score (common in OSV/GHSA data).
  const findings = await db.scanFinding.findMany({
    where: {
      scanRunId,
      findingType: "cve",
      reachableAssessedAt: null,
      confirmedReachable: false,
      OR: [
        { cvssScore: { gte: threshold } },
        { cvssScore: null, severity: { in: ["critical", "high"] } },
      ],
    },
    include: { component: { select: { name: true, version: true, ecosystem: true, purl: true } } },
  });

  if (findings.length === 0) {
    logger.info("[reachabilityService] no findings to assess");
    return;
  }

  logger.info(
    { count: findings.length, threshold },
    "[reachabilityService] assessing reachability",
  );

  for (const finding of findings) {
    // Skip if already marked reachable via SAST triage hints
    if (finding.confirmedReachable) continue;

    const component = finding.component as { name: string; version: string | null; ecosystem: string | null; purl: string };

    const osvVuln: OsvVulnForExtraction = {
      id: finding.osvId,
      cveId: finding.cveId,
      ecosystem: component.ecosystem ?? "npm",
      packageName: component.name,
      summary: finding.summary,
      details: (finding.detailJson as Record<string, unknown> | null)?.details as string | null ?? null,
      modified: (finding.detailJson as Record<string, unknown> | null)?.modified as string | null ?? null,
    };

    // Step 1: get or extract vulnerable functions (cached globally)
    const knowledge = await getOrExtract(osvVuln, orgId, db);

    if (knowledge.vulnerableFunctions.length === 0) {
      // Can't assess — no function names identified
      await db.scanFinding.update({
        where: { id: finding.id },
        data: {
          reachableAssessedAt: new Date(),
          reachableReasoning: "No specific vulnerable functions identified from advisory",
        },
      });
      continue;
    }

    // Step 2: ripgrep scope for each function name
    let allHits: GrepHit[] = [];
    let matchedFunction = "";

    for (const fn of knowledge.vulnerableFunctions) {
      const hits = await ripgrepForFunction(fn, scopeWorkingDir);
      if (hits.length > 0) {
        allHits = hits;
        matchedFunction = fn;
        break; // one confirmed hit is enough to warrant LLM confirmation
      }
    }

    if (allHits.length === 0) {
      // No references in scope — high confidence not reachable
      logger.info(
        { findingId: finding.id, functions: knowledge.vulnerableFunctions },
        "[reachabilityService] no references found — marking not reachable",
      );
      await db.scanFinding.update({
        where: { id: finding.id },
        data: {
          confirmedReachable: false,
          reachableReasoning: `No references to ${knowledge.vulnerableFunctions.join(", ")} found in scope`,
          reachableAssessedAt: new Date(),
        },
      });
      continue;
    }

    // Step 3: LLM confirms whether it's actually a vulnerable call
    logger.info(
      { findingId: finding.id, matchedFunction, hits: allHits.length },
      "[reachabilityService] hits found — asking LLM to confirm",
    );

    const confirmation = await confirmReachabilityWithLlm(
      finding as ScanFinding & { component: { name: string; version: string | null } },
      matchedFunction,
      allHits,
      orgId,
    );

    if (!confirmation) {
      // LLM not available — record grep hit as tentative
      await db.scanFinding.update({
        where: { id: finding.id },
        data: {
          reachableAssessedAt: new Date(),
          reachableReasoning: `References to '${matchedFunction}' found in scope but LLM confirmation unavailable`,
        },
      });
      continue;
    }

    await db.scanFinding.update({
      where: { id: finding.id },
      data: {
        confirmedReachable: confirmation.reachable,
        reachableReasoning: confirmation.reasoning,
        reachableAssessedAt: new Date(),
        reachableModel: confirmation.model,
      },
    });

    logger.info(
      { findingId: finding.id, reachable: confirmation.reachable, confidence: confirmation.confidence },
      "[reachabilityService] reachability assessed",
    );
  }

  // Update scan-level counter
  const reachableCount = await db.scanFinding.count({
    where: { scanRunId, confirmedReachable: true },
  });
  await db.scanRun.update({
    where: { id: scanRunId },
    data: { confirmedReachableCount: reachableCount },
  });
}
