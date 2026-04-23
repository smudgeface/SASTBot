/**
 * LLM-assisted SAST finding triage.
 *
 * For each pending finding, builds a prompt with:
 *   - The SAST finding details + code snippet
 *   - High-severity SCA findings for the same scope (for reachability hints)
 *
 * Uses tool_use on anthropic-messages for guaranteed structured output.
 * Falls back to JSON-in-prompt + Zod parse + one retry on other formats.
 * Enforces the per-scan token budget set in AppSettings.
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

// Tool schema sent to Anthropic for tool_use structured output
const TRIAGE_TOOL_SCHEMA = {
  type: "object",
  properties: {
    triage: {
      type: "string",
      enum: ["confirmed", "false_positive"],
      description: "Whether this is a real vulnerability or a false positive",
    },
    confidence: {
      type: "number",
      description: "Confidence score 0.0-1.0",
    },
    reasoning: {
      type: "string",
      description: "Brief explanation of the triage decision",
    },
    confirmed_reachable_sca_ids: {
      type: "array",
      items: { type: "string" },
      description: "IDs of SCA dependency findings that appear reachable from this code",
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
  finding: {
    ruleId: string;
    ruleName: string | null;
    ruleMessage: string | null;
    severity: string;
    cweIds: string[];
    filePath: string;
    startLine: number;
    snippet: string | null;
  },
  scaHints: ScaHint[],
): string {
  const cweStr = finding.cweIds.length > 0 ? finding.cweIds.join(", ") : "none";

  let prompt = `You are a security code reviewer. Analyze this static analysis finding and classify it.

## SAST Finding
Rule: ${finding.ruleId}${finding.ruleName ? ` - ${finding.ruleName}` : ""}
Severity: ${finding.severity}
CWE: ${cweStr}
${finding.ruleMessage ? `Description: ${finding.ruleMessage}\n` : ""}
## Location
${finding.filePath}:${finding.startLine}

## Code
\`\`\`
${finding.snippet ?? "(no snippet available)"}
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
  "confirmed_reachable_sca_ids": ["<id>", ...]
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

  if (!settings.llmAssistanceEnabled) return;
  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    logger.info("[llmTriageService] LLM not fully configured — skipping triage");
    return;
  }

  // Load pending SAST findings ordered by severity (high → low)
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const pending = await db.sastFinding.findMany({
    where: { scanRunId, triageStatus: "pending" },
  });
  pending.sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );

  if (pending.length === 0) {
    logger.info("[llmTriageService] no pending findings to triage");
    return;
  }

  // Load high/critical SCA findings for reachability context
  const scaFindings = await db.scanFinding.findMany({
    where: {
      scanRunId,
      findingType: "cve",
      severity: { in: ["critical", "high"] },
    },
    include: { component: { select: { name: true, version: true } } },
  });
  const scaHints: ScaHint[] = scaFindings.map((f) => ({
    id: f.id,
    componentName: (f.component as { name: string }).name,
    version: (f.component as { version: string | null }).version,
    cveId: f.cveId,
    osvId: f.osvId,
    summary: f.summary,
    cvssScore: f.cvssScore,
  }));

  const budget = settings.llmTriageTokenBudget;
  const useToolUse = (settings.llmApiFormat ?? "openai-chat") === "anthropic-messages";

  logger.info(
    { count: pending.length, budget, useToolUse },
    "[llmTriageService] starting triage",
  );

  for (const finding of pending) {
    // Check budget before each call
    const run = await db.scanRun.findUnique({
      where: { id: scanRunId },
      select: { llmInputTokens: true, llmOutputTokens: true },
    });
    const tokensUsed = (run?.llmInputTokens ?? 0) + (run?.llmOutputTokens ?? 0);
    if (tokensUsed >= budget) {
      const remaining = pending.length - pending.indexOf(finding);
      logger.warn({ remaining, budget }, "[llmTriageService] budget exhausted");
      await appendWarning(scanRunId, db, {
        code: "triage_budget_exhausted",
        message: `LLM token budget (${budget}) exhausted; ${remaining} finding(s) left pending.`,
        context: { remaining },
      });
      break;
    }

    const prompt = buildPrompt(finding, scaHints);
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
      logger.warn({ findingId: finding.id, err: msg }, "[llmTriageService] LLM call failed");
      await db.sastFinding.update({
        where: { id: finding.id },
        data: { triageStatus: "error", triageReasoning: `LLM error: ${msg}` },
      });
      await appendWarning(scanRunId, db, {
        code: "llm_transient_error",
        message: `LLM call failed for finding ${finding.id}: ${msg}`,
        context: { findingId: finding.id },
      });
      continue;
    }

    if (callResult === null) {
      // LLM became unconfigured mid-scan (toggle flipped) — stop gracefully
      logger.info("[llmTriageService] callLlm returned null — stopping");
      break;
    }

    // Parse response
    parsed = parseJsonResponse(callResult.text, TriageResponseSchema);

    // One retry on parse failure with error feedback
    if (parsed === null && callResult !== null) {
      logger.warn(
        { findingId: finding.id, raw: callResult.text.slice(0, 200) },
        "[llmTriageService] parse failed — retrying with error feedback",
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
      await db.sastFinding.update({
        where: { id: finding.id },
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

    // Persist triage result
    await db.sastFinding.update({
      where: { id: finding.id },
      data: {
        triageStatus: parsed.triage,
        triageConfidence: parsed.confidence,
        triageReasoning: parsed.reasoning,
        triageModel: callResult.model,
        triageInputTokens: callResult.inputTokens,
        triageOutputTokens: callResult.outputTokens,
      },
    });

    // Apply opportunistic reachability hints from SAST triage
    const reachableIds = parsed.confirmed_reachable_sca_ids ?? [];
    if (reachableIds.length > 0) {
      await db.scanFinding.updateMany({
        where: {
          id: { in: reachableIds },
          scanRunId,
        },
        data: {
          confirmedReachable: true,
          reachableViaSastFingerprint: finding.fingerprint,
          reachableReasoning: `Identified as reachable by LLM during SAST triage of ${finding.ruleId}`,
          reachableAssessedAt: new Date(),
          reachableModel: callResult.model,
        },
      });
    }

    logger.info(
      { findingId: finding.id, triage: parsed.triage, confidence: parsed.confidence },
      "[llmTriageService] finding triaged",
    );
  }

  // Update confirmedReachableCount
  const reachableCount = await db.scanFinding.count({
    where: { scanRunId, confirmedReachable: true },
  });
  await db.scanRun.update({
    where: { id: scanRunId },
    data: { confirmedReachableCount: reachableCount },
  });
}

// ---------------------------------------------------------------------------
// Warning helper (inline — avoids circular import with worker)
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
