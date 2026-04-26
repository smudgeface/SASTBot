/**
 * CveKnowledge — global cache of vulnerable function names per CVE.
 *
 * For each OSV vulnerability, asks the LLM to extract the names of the
 * specific functions an application must call to be vulnerable. The result
 * is stored in the CveKnowledge table and reused across all future scans —
 * extraction only runs once per CVE (or when the OSV advisory is updated).
 *
 * Regex extraction was intentionally skipped: confidence in pattern-count
 * as a quality signal is poor, and LLM extraction is straightforwardly
 * more accurate at negligible cost (~50–100 tokens per CVE).
 */
import type { CveKnowledge, Prisma, PrismaClient } from "@prisma/client";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { callLlm, parseJsonResponse } from "./llmClient.js";

const logger = pino({ level: loadConfig().logLevel, name: "cveKnowledgeService" });

type Tx = PrismaClient | Prisma.TransactionClient;

// ---------------------------------------------------------------------------
// OSV vulnerability shape (subset we need)
// ---------------------------------------------------------------------------

export interface OsvVulnForExtraction {
  id: string;           // OSV id e.g. "GHSA-35jh-r3h4-6jhm"
  cveId?: string | null;
  ecosystem: string;
  packageName: string;
  summary?: string | null;
  details?: string | null;
  modified?: string | null;
}

// ---------------------------------------------------------------------------
// LLM extraction
// ---------------------------------------------------------------------------

const ExtractionResponseSchema = z.object({
  vulnerable_functions: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
});

const EXTRACTION_TOOL_SCHEMA = {
  type: "object",
  properties: {
    vulnerable_functions: {
      type: "array",
      items: { type: "string" },
      description:
        "Names of the specific functions/methods an application must call to be vulnerable. Use bare names (e.g. 'template', 'merge') not fully-qualified (no 'lodash.template' or '_.template'). Empty array if no specific function can be identified.",
    },
    confidence: {
      type: "number",
      description: "0.0–1.0 confidence that these are the correct vulnerable function names",
    },
    reasoning: {
      type: "string",
      description: "One sentence explaining how you identified these functions",
    },
  },
  required: ["vulnerable_functions", "confidence", "reasoning"],
};

async function extractViaLlm(
  vuln: OsvVulnForExtraction,
  orgId: string | null,
): Promise<{ functions: string[]; confidence: number; reasoning: string; model: string } | null> {
  const text = [vuln.summary, vuln.details].filter(Boolean).join("\n\n");
  if (!text.trim()) {
    return { functions: [], confidence: 0, reasoning: "No advisory text available", model: "" };
  }

  const prompt = `You are a security researcher. Given the vulnerability advisory below, identify the specific function names that an application must call to be exposed to this vulnerability.

## Package
${vuln.packageName} (${vuln.ecosystem})

## Advisory
${text.slice(0, 3000)}

Extract the vulnerable function names. Return only function/method names (not class names, not module names). If no specific function can be determined, return an empty array.`;

  const useToolUse = true; // always anthropic-messages in this project
  const result = await callLlm({
    orgId,
    prompt,
    maxTokens: 256,
    toolName: useToolUse ? "submit_extraction" : undefined,
    toolSchema: useToolUse ? EXTRACTION_TOOL_SCHEMA : undefined,
  });

  if (!result) return null;

  const parsed = parseJsonResponse(result.text, ExtractionResponseSchema);
  if (!parsed) {
    logger.warn({ osvId: vuln.id }, "[cveKnowledgeService] LLM returned unparseable extraction");
    return null;
  }

  return {
    functions: parsed.vulnerable_functions,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
    model: result.model,
  };
}

// ---------------------------------------------------------------------------
// Main entrypoint — get or extract
// ---------------------------------------------------------------------------

export async function getOrExtract(
  vuln: OsvVulnForExtraction,
  orgId: string | null,
  client: Tx,
): Promise<CveKnowledge> {
  const db = client as PrismaClient;

  // Check cache
  const existing = await db.cveKnowledge.findUnique({ where: { osvId: vuln.id } });

  if (existing) {
    // Re-extract only if the OSV advisory was updated since we last extracted.
    // Compare truncated to seconds to avoid microsecond precision mismatches
    // between OSV ISO strings and Postgres timestamptz round-trips.
    const osvModified = vuln.modified ? new Date(vuln.modified) : null;
    const cacheModified = existing.osvModifiedAt;
    const stale =
      osvModified !== null &&
      cacheModified !== null &&
      Math.floor(osvModified.getTime() / 1000) > Math.floor(cacheModified.getTime() / 1000);

    if (!stale) {
      logger.info({ osvId: vuln.id }, "[cveKnowledgeService] cache hit — reusing");
      return existing;
    }
    logger.info(
      { osvId: vuln.id },
      "[cveKnowledgeService] OSV advisory updated — re-extracting",
    );
  }

  // Extract via LLM
  logger.info({ osvId: vuln.id }, "[cveKnowledgeService] extracting vulnerable functions");
  const extraction = await extractViaLlm(vuln, orgId);

  const data = {
    osvId: vuln.id,
    cveId: vuln.cveId ?? null,
    ecosystem: vuln.ecosystem,
    packageName: vuln.packageName,
    vulnerableFunctions: extraction?.functions ?? [],
    extractionMethod: extraction ? "llm" : "none",
    extractionConfidence: extraction?.confidence ?? 0,
    extractionModel: extraction?.model || null,
    extractionReasoning: extraction?.reasoning ?? null,
    osvModifiedAt: vuln.modified ? new Date(vuln.modified) : null,
  };

  return db.cveKnowledge.upsert({
    where: { osvId: vuln.id },
    create: data,
    update: data,
  });
}
