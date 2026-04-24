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
        return { file: m[1], line: parseInt(m[2], 10), text: m[3] };
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
  issue: ScaIssue,
  functionName: string,
  hits: GrepHit[],
  orgId: string | null,
): Promise<{ reachable: boolean; confidence: number; reasoning: string; model: string } | null> {
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

Respond with whether the vulnerability appears reachable from this codebase.`;

  const result = await callLlm(
    { orgId, prompt, maxTokens: 256, toolName: "submit_reachability", toolSchema: REACHABILITY_TOOL_SCHEMA },
    { skipEnabledCheck: false },
  );

  if (!result) return null;

  const parsed = parseJsonResponse(result.text, ReachabilityResponseSchema);
  if (!parsed) {
    logger.warn({ issueId: issue.id }, "[reachabilityService] LLM returned unparseable response");
    return null;
  }

  return { reachable: parsed.reachable, confidence: parsed.confidence, reasoning: parsed.reasoning, model: result.model };
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

  const threshold = settings.reachabilityCvssThreshold;

  // Query ScaIssue rows detected in this scan that meet severity threshold
  const issues = await db.scaIssue.findMany({
    where: {
      scopeId,
      lastSeenScanRunId: scanRunId,
      latestFindingType: "cve",
      OR: [
        { latestCvssScore: { gte: threshold } },
        { latestCvssScore: null, latestSeverity: { in: ["critical", "high"] } },
      ],
    },
  });

  if (issues.length === 0) {
    logger.info("[reachabilityService] no issues to assess");
    return;
  }

  logger.info(
    { count: issues.length, threshold },
    "[reachabilityService] assessing reachability",
  );

  for (const issue of issues) {
    // Already marked reachable (e.g. via SAST triage hints) — skip LLM
    if (issue.confirmedReachable) continue;

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
      continue;
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
      continue;
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
      continue;
    }

    await db.scaIssue.update({
      where: { id: issue.id },
      data: {
        confirmedReachable: confirmation.reachable,
        reachableReasoning: confirmation.reasoning,
        reachableAssessedAt: new Date(),
        reachableModel: confirmation.model,
      },
    });

    logger.info(
      { issueId: issue.id, reachable: confirmation.reachable, confidence: confirmation.confidence },
      "[reachabilityService] reachability assessed",
    );
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
