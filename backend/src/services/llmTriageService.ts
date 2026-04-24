/**
 * LLM-assisted SAST issue triage.
 *
 * Queries SastIssue rows where triageStatus is pending/error AND
 * lastSeenScanRunId matches the current scan, then writes triage decisions
 * back to the issue (not the detection). Reachability hints from triage
 * update ScaIssue rows.
 */
import type { Prisma, PrismaClient } from "@prisma/client";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { callLlm, parseJsonResponse } from "./llmClient.js";
import { getOrCreateSettings } from "./settingsService.js";

const logger = pino({ level: loadConfig().logLevel, name: "llmTriageService" });

type Tx = PrismaClient | Prisma.TransactionClient;

// ---------------------------------------------------------------------------
// Response schema
// ---------------------------------------------------------------------------

const TriageResponseSchema = z.object({
  triage: z.enum(["confirmed", "false_positive"]),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
  confirmed_reachable_sca_ids: z.array(z.string()).optional(),
});
type TriageResponse = z.infer<typeof TriageResponseSchema>;

const TRIAGE_TOOL_SCHEMA = {
  type: "object",
  properties: {
    triage: {
      type: "string",
      enum: ["confirmed", "false_positive"],
      description: "Whether this is a real vulnerability or a false positive",
    },
    confidence: { type: "number", description: "Confidence score 0.0-1.0" },
    reasoning: { type: "string", description: "Brief explanation of the triage decision" },
    confirmed_reachable_sca_ids: {
      type: "array",
      items: { type: "string" },
      description: "IDs of SCA issues (ScaIssue.id) that appear reachable from this code",
    },
  },
  required: ["triage", "confidence", "reasoning", "confirmed_reachable_sca_ids"],
};

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

interface ScaHint {
  id: string;
  componentName: string;
  version: string | null;
  cveId: string | null;
  osvId: string;
  summary: string | null;
  cvssScore: number | null;
}

function buildPrompt(
  issue: {
    latestRuleId: string;
    latestRuleName: string | null;
    latestRuleMessage: string | null;
    latestSeverity: string;
    latestCweIds: string[];
    latestFilePath: string;
    latestStartLine: number;
    latestSnippet: string | null;
  },
  scaHints: ScaHint[],
): string {
  const cweStr = issue.latestCweIds.length > 0 ? issue.latestCweIds.join(", ") : "none";

  let prompt = `You are a security code reviewer. Analyze this static analysis finding and classify it.

## SAST Finding
Rule: ${issue.latestRuleId}${issue.latestRuleName ? ` - ${issue.latestRuleName}` : ""}
Severity: ${issue.latestSeverity}
CWE: ${cweStr}
${issue.latestRuleMessage ? `Description: ${issue.latestRuleMessage}\n` : ""}
## Location
${issue.latestFilePath}:${issue.latestStartLine}

## Code
\`\`\`
${issue.latestSnippet ?? "(no snippet available)"}
\`\`\`
`;

  if (scaHints.length > 0) {
    prompt += "\n## Known dependency vulnerabilities in this scope\n";
    for (const h of scaHints) {
      const ver = h.version ? `@${h.version}` : "";
      const id = h.cveId ?? h.osvId;
      const score = h.cvssScore != null ? ` (CVSS ${h.cvssScore.toFixed(1)})` : "";
      prompt += `- [id=${h.id}] ${h.componentName}${ver} - ${id}${score}: ${h.summary ?? "no summary"}\n`;
    }
  }

  prompt += `
## Task
Classify the SAST finding as "confirmed" (real vulnerability) or "false_positive".
Additionally, for each dependency vulnerability listed above, determine if the code shown appears to call the vulnerable component's affected functionality.

Respond with ONLY valid JSON:
{
  "triage": "confirmed" | "false_positive",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "confirmed_reachable_sca_ids": ["<ScaIssue id>", ...]
}`;

  return prompt;
}

// ---------------------------------------------------------------------------
// Main entrypoint
// ---------------------------------------------------------------------------

export async function triageFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  client: Tx,
): Promise<void> {
  const db = client as PrismaClient;
  const settings = await getOrCreateSettings(orgId);

  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    logger.info("[llmTriageService] LLM not fully configured — skipping triage");
    return;
  }

  // Load SastIssue rows needing triage in this scan, ordered by severity
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const pending = await db.sastIssue.findMany({
    where: {
      scopeId,
      lastSeenScanRunId: scanRunId,
      triageStatus: { in: ["pending", "error"] },
    },
  });
  pending.sort(
    (a, b) =>
      severityOrder.indexOf(a.latestSeverity) - severityOrder.indexOf(b.latestSeverity),
  );

  if (pending.length === 0) {
    logger.info("[llmTriageService] no pending issues to triage");
    return;
  }

  // Load high/critical ScaIssue rows for reachability context
  const scaIssues = await db.scaIssue.findMany({
    where: {
      scopeId,
      lastSeenScanRunId: scanRunId,
      latestFindingType: "cve",
      latestSeverity: { in: ["critical", "high"] },
    },
  });
  const scaHints: ScaHint[] = scaIssues.map((i) => ({
    id: i.id,
    componentName: i.packageName,
    version: i.latestPackageVersion,
    cveId: i.latestCveId,
    osvId: i.osvId,
    summary: i.latestSummary,
    cvssScore: i.latestCvssScore,
  }));

  const budget = settings.llmTriageTokenBudget;
  const useToolUse = (settings.llmApiFormat ?? "openai-chat") === "anthropic-messages";

  logger.info(
    { count: pending.length, budget, useToolUse },
    "[llmTriageService] starting triage",
  );

  for (const issue of pending) {
    const run = await db.scanRun.findUnique({
      where: { id: scanRunId },
      select: { llmInputTokens: true, llmOutputTokens: true },
    });
    const tokensUsed = (run?.llmInputTokens ?? 0) + (run?.llmOutputTokens ?? 0);
    if (tokensUsed >= budget) {
      const remaining = pending.length - pending.indexOf(issue);
      logger.warn({ remaining, budget }, "[llmTriageService] budget exhausted");
      await appendWarning(scanRunId, db, {
        code: "triage_budget_exhausted",
        message: `LLM token budget (${budget}) exhausted; ${remaining} issue(s) left pending.`,
        context: { remaining },
      });
      break;
    }

    const prompt = buildPrompt(issue, scaHints);
    let parsed: TriageResponse | null = null;
    let callResult;

    try {
      callResult = await callLlm({
        scanRunId,
        orgId,
        prompt,
        maxTokens: 512,
        toolName: useToolUse ? "submit_triage" : undefined,
        toolSchema: useToolUse ? TRIAGE_TOOL_SCHEMA : undefined,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn({ issueId: issue.id, err: msg }, "[llmTriageService] LLM call failed");
      await db.sastIssue.update({
        where: { id: issue.id },
        data: { triageStatus: "error", triageReasoning: `LLM error: ${msg}` },
      });
      await appendWarning(scanRunId, db, {
        code: "llm_transient_error",
        message: `LLM call failed for issue ${issue.id}: ${msg}`,
        context: { issueId: issue.id },
      });
      continue;
    }

    if (callResult === null) {
      logger.info("[llmTriageService] callLlm returned null — stopping");
      break;
    }

    parsed = parseJsonResponse(callResult.text, TriageResponseSchema);

    if (parsed === null) {
      logger.warn(
        { issueId: issue.id, raw: callResult.text.slice(0, 200) },
        "[llmTriageService] parse failed — retrying",
      );
      const retryPrompt = `${prompt}\n\nYour previous response was not valid JSON. Please respond with ONLY the JSON object, no other text.`;
      try {
        const retryResult = await callLlm({
          scanRunId,
          orgId,
          prompt: retryPrompt,
          maxTokens: 512,
          toolName: useToolUse ? "submit_triage" : undefined,
          toolSchema: useToolUse ? TRIAGE_TOOL_SCHEMA : undefined,
        });
        if (retryResult) {
          parsed = parseJsonResponse(retryResult.text, TriageResponseSchema);
        }
      } catch {
        // fall through to error status
      }
    }

    if (parsed === null) {
      await db.sastIssue.update({
        where: { id: issue.id },
        data: {
          triageStatus: "error",
          triageReasoning: "LLM returned malformed JSON after retry",
          triageModel: callResult.model,
          triageInputTokens: callResult.inputTokens,
          triageOutputTokens: callResult.outputTokens,
        },
      });
      continue;
    }

    // Persist triage decision on the SastIssue
    await db.sastIssue.update({
      where: { id: issue.id },
      data: {
        triageStatus: parsed.triage,
        triageConfidence: parsed.confidence,
        triageReasoning: parsed.reasoning,
        triageModel: callResult.model,
        triageInputTokens: callResult.inputTokens,
        triageOutputTokens: callResult.outputTokens,
      },
    });

    // Apply opportunistic reachability hints to ScaIssue rows
    const reachableIds = parsed.confirmed_reachable_sca_ids ?? [];
    if (reachableIds.length > 0) {
      await db.scaIssue.updateMany({
        where: { id: { in: reachableIds }, scopeId },
        data: {
          confirmedReachable: true,
          reachableViaSastFingerprint: issue.fingerprint,
          reachableReasoning: `Identified as reachable by LLM during SAST triage of ${issue.latestRuleId}`,
          reachableAssessedAt: new Date(),
          reachableModel: callResult.model,
        },
      });
    }

    logger.info(
      { issueId: issue.id, triage: parsed.triage, confidence: parsed.confidence },
      "[llmTriageService] issue triaged",
    );
  }

  // Update scan-level reachable count from ScaIssue
  const reachableCount = await db.scaIssue.count({
    where: { scopeId, lastSeenScanRunId: scanRunId, confirmedReachable: true },
  });
  await db.scanRun.update({
    where: { id: scanRunId },
    data: { confirmedReachableCount: reachableCount },
  });
}

// ---------------------------------------------------------------------------
// Warning helper
// ---------------------------------------------------------------------------

interface ScanWarning {
  code: string;
  message: string;
  context?: Record<string, unknown>;
}

async function appendWarning(
  scanRunId: string,
  db: PrismaClient,
  warning: ScanWarning,
): Promise<void> {
  const run = await db.scanRun.findUnique({
    where: { id: scanRunId },
    select: { warnings: true },
  });
  const current = Array.isArray(run?.warnings) ? (run!.warnings as unknown as ScanWarning[]) : [];
  await db.scanRun.update({
    where: { id: scanRunId },
    data: { warnings: [...current, warning] as unknown as Prisma.InputJsonValue },
  });
}
