/**
 * Low-level LLM client.
 *
 * Supports:
 *   anthropic-messages — Anthropic Messages API with tool_use for structured output
 *   openai-chat        — OpenAI Chat Completions with response_format JSON mode
 *   openai-completions — Legacy OpenAI Completions (JSON-in-prompt)
 *
 * Returns null (no error) when LLM assistance is disabled or not configured,
 * so callers can degrade gracefully without error handling at every call site.
 */
import type { Prisma, PrismaClient } from "@prisma/client";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { decodeCredential } from "./credentialService.js";
import { getOrCreateSettings } from "./settingsService.js";

const logger = pino({ level: loadConfig().logLevel, name: "llmClient" });

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface LlmCallInput {
  scanRunId?: string;
  orgId?: string | null;
  prompt: string;
  maxTokens?: number;
  /** If set, use tool_use with this tool name (anthropic-messages only). */
  toolName?: string;
  /** JSON Schema for the tool input (anthropic-messages only). */
  toolSchema?: Record<string, unknown>;
}

export interface LlmCallResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  latencyMs: number;
}

// ---------------------------------------------------------------------------
// Anthropic Messages API shapes
// ---------------------------------------------------------------------------

interface AnthropicTool {
  name: string;
  description?: string;
  input_schema: Record<string, unknown>;
}

interface AnthropicRequest {
  model: string;
  max_tokens: number;
  messages: { role: string; content: string }[];
  tools?: AnthropicTool[];
  tool_choice?: { type: "tool"; name: string };
}

interface AnthropicResponse {
  content: Array<
    | { type: "text"; text: string }
    | { type: "tool_use"; name: string; input: Record<string, unknown> }
  >;
  usage: { input_tokens: number; output_tokens: number };
  model: string;
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions shapes
// ---------------------------------------------------------------------------

interface OpenAiRequest {
  model: string;
  messages: { role: string; content: string }[];
  max_tokens?: number;
  response_format?: { type: "json_object" };
}

interface OpenAiResponse {
  choices: Array<{ message: { content: string | null } }>;
  usage: { prompt_tokens: number; completion_tokens: number };
  model: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function doFetch(
  url: string,
  headers: Record<string, string>,
  body: unknown,
  retries = 1,
): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      });
      if (resp.status >= 500 && attempt < retries) {
        logger.warn({ status: resp.status, attempt }, "[llmClient] 5xx — retrying");
        await sleep(1000);
        continue;
      }
      return resp;
    } catch (err) {
      const isTimeout =
        err instanceof Error &&
        (err.name === "TimeoutError" || err.name === "AbortError" || err.message.includes("fetch"));
      if (isTimeout && attempt < retries) {
        logger.warn({ attempt }, "[llmClient] network error — retrying");
        await sleep(1000);
        continue;
      }
      throw err;
    }
  }
  throw new Error("unreachable");
}

async function incrementTokenCounters(
  scanRunId: string,
  inputTokens: number,
  outputTokens: number,
): Promise<void> {
  // Use raw SQL increment to avoid read-modify-write races.
  await (prisma as PrismaClient).$executeRaw`
    UPDATE scan_runs
    SET
      llm_input_tokens  = llm_input_tokens  + ${inputTokens},
      llm_output_tokens = llm_output_tokens + ${outputTokens},
      llm_request_count = llm_request_count + 1
    WHERE id = ${scanRunId}::uuid
  `;
}

// Lazy import to avoid circular deps at module load time
let prisma: PrismaClient;
async function getPrisma(): Promise<PrismaClient> {
  if (!prisma) {
    const { prisma: p } = await import("../db.js");
    prisma = p;
  }
  return prisma;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function callLlm(
  input: LlmCallInput,
): Promise<LlmCallResult | null> {
  const db = await getPrisma();
  const settings = await getOrCreateSettings(input.orgId ?? null);

  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    logger.warn("[llmClient] LLM base URL / model / credential not configured");
    return null;
  }

  const decoded = await decodeCredential(settings.llmCredentialId, db);
  if (decoded.kind !== "llm_api_key") {
    logger.warn("[llmClient] LLM credential is not an llm_api_key");
    return null;
  }
  const apiKey = decoded.value;
  const baseUrl = settings.llmBaseUrl.replace(/\/$/, "");
  const model = settings.llmModel;
  const format = settings.llmApiFormat ?? "openai-chat";
  const maxTokens = input.maxTokens ?? 1024;

  const start = Date.now();
  let text: string;
  let inputTokens: number;
  let outputTokens: number;
  let responseModel: string;

  if (format === "anthropic-messages") {
    const url = `${baseUrl}/v1/messages`;
    const body: AnthropicRequest = {
      model,
      max_tokens: maxTokens,
      messages: [{ role: "user", content: input.prompt }],
    };

    // Use tool_use when a schema is provided — forces structured JSON output.
    if (input.toolName && input.toolSchema) {
      body.tools = [
        {
          name: input.toolName,
          description: "Submit structured analysis result",
          input_schema: input.toolSchema,
        },
      ];
      body.tool_choice = { type: "tool", name: input.toolName };
    }

    const resp = await doFetch(url, {
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    }, body);

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      throw Object.assign(new Error(`Anthropic API error ${resp.status}: ${errText}`), {
        httpStatus: resp.status,
      });
    }
    const data = (await resp.json()) as AnthropicResponse;

    // Extract text from tool_use result or plain text block.
    const toolBlock = data.content.find((c) => c.type === "tool_use");
    if (toolBlock && toolBlock.type === "tool_use") {
      text = JSON.stringify(toolBlock.input);
    } else {
      const textBlock = data.content.find((c) => c.type === "text");
      text = textBlock && textBlock.type === "text" ? textBlock.text : "";
    }
    inputTokens = data.usage.input_tokens;
    outputTokens = data.usage.output_tokens;
    responseModel = data.model;
  } else {
    // openai-chat or openai-completions
    const url =
      format === "openai-completions"
        ? `${baseUrl}/v1/completions`
        : `${baseUrl}/v1/chat/completions`;

    const body: OpenAiRequest = {
      model,
      messages: [{ role: "user", content: input.prompt }],
      max_tokens: maxTokens,
    };
    if (format === "openai-chat") {
      body.response_format = { type: "json_object" };
    }

    const resp = await doFetch(url, { Authorization: `Bearer ${apiKey}` }, body);

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      throw Object.assign(new Error(`OpenAI API error ${resp.status}: ${errText}`), {
        httpStatus: resp.status,
      });
    }
    const data = (await resp.json()) as OpenAiResponse;
    text = data.choices[0]?.message?.content ?? "";
    inputTokens = data.usage.prompt_tokens;
    outputTokens = data.usage.completion_tokens;
    responseModel = data.model;
  }

  const latencyMs = Date.now() - start;
  logger.info(
    { model: responseModel, inputTokens, outputTokens, latencyMs },
    "[llmClient] call complete",
  );

  if (input.scanRunId) {
    await incrementTokenCounters(input.scanRunId, inputTokens, outputTokens);
  }

  return { text, inputTokens, outputTokens, model: responseModel, latencyMs };
}

// ---------------------------------------------------------------------------
// Structured JSON parse with Zod
// ---------------------------------------------------------------------------

export function parseJsonResponse<T>(
  text: string,
  schema: z.ZodSchema<T>,
): T | null {
  try {
    // Strip markdown code fences if present (some models wrap JSON in ```json)
    const clean = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "").trim();
    const parsed: unknown = JSON.parse(clean);
    const result = schema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Connection check (no tool_use, minimal tokens)
// ---------------------------------------------------------------------------

export async function checkLlmConnection(orgId: string | null = null): Promise<{
  success: boolean;
  latencyMs: number;
  model: string;
  inputTokens: number;
  outputTokens: number;
  error?: string;
}> {
  try {
    const result = await callLlm(
      { orgId, prompt: 'Reply with exactly the word "ok"', maxTokens: 20 },
    );
    if (result === null) {
      return {
        success: false,
        latencyMs: 0,
        model: "",
        inputTokens: 0,
        outputTokens: 0,
        error: "LLM assistance not configured",
      };
    }
    return {
      success: true,
      latencyMs: result.latencyMs,
      model: result.model,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
    };
  } catch (err) {
    const e = err as Error & { httpStatus?: number };
    let error: string;
    if (e.httpStatus === 401) {
      error = "Authentication failed — check API key credential";
    } else if (e.httpStatus === 404) {
      error = "Model not found — check llm_model setting";
    } else if (
      e.message.includes("ECONNREFUSED") ||
      e.message.includes("fetch") ||
      e.message.includes("TimeoutError") ||
      e.name === "TimeoutError"
    ) {
      error = "Could not reach LLM base URL — check network and URL";
    } else {
      error = e.message;
    }
    return { success: false, latencyMs: 0, model: "", inputTokens: 0, outputTokens: 0, error };
  }
}

// ---------------------------------------------------------------------------
// LLM-generated issue summaries
// ---------------------------------------------------------------------------

export interface SastSummaryContext {
  ruleId: string;
  ruleName: string | null;
  ruleMessage: string | null;
  filePath: string;
  snippet: string | null;
  scanRunId?: string;
  orgId?: string | null;
}

export interface ScaSummaryContext {
  packageName: string;
  version: string | null;
  osvId: string;
  cveId: string | null;
  cvssScore: number | null;
  osvSummary: string | null;
  scanRunId?: string;
  orgId?: string | null;
}

const SummarySchema = z.object({ summary: z.string() });

export async function generateIssueSummary(
  kind: "sast",
  input: SastSummaryContext,
): Promise<string | null>;
export async function generateIssueSummary(
  kind: "sca",
  input: ScaSummaryContext,
): Promise<string | null>;
export async function generateIssueSummary(
  kind: "sast" | "sca",
  input: SastSummaryContext | ScaSummaryContext,
): Promise<string | null> {
  let prompt: string;

  if (kind === "sast") {
    const i = input as SastSummaryContext;
    const snippet = i.snippet ? `\nCode:\n\`\`\`\n${i.snippet.slice(0, 500)}\n\`\`\`` : "";
    prompt = `Write a ≤100-char plain English sentence starting with a verb that summarizes this SAST finding.
Rule: ${i.ruleId}${i.ruleName ? ` – ${i.ruleName}` : ""}
${i.ruleMessage ? `Message: ${i.ruleMessage}\n` : ""}File: ${i.filePath}${snippet}
Reply with ONLY valid JSON: {"summary": "<your sentence>"}`;
  } else {
    const i = input as ScaSummaryContext;
    const id = i.cveId ?? i.osvId;
    const cvss = i.cvssScore != null ? ` (CVSS ${i.cvssScore.toFixed(1)})` : "";
    const ver = i.version ? `@${i.version}` : "";
    prompt = `Write a ≤100-char plain English sentence starting with a verb that summarizes this SCA vulnerability's impact.
Package: ${i.packageName}${ver}
ID: ${id}${cvss}
${i.osvSummary ? `Description: ${i.osvSummary}\n` : ""}Reply with ONLY valid JSON: {"summary": "<your sentence>"}`;
  }

  const result = await callLlm({
    scanRunId: input.scanRunId,
    orgId: input.orgId ?? null,
    prompt,
    maxTokens: 80,
  });

  if (!result) return null;

  const parsed = parseJsonResponse(result.text, SummarySchema);
  if (!parsed) {
    // Plain text fallback for models that ignore the JSON instruction
    const text = result.text.trim().replace(/^["']|["']$/g, "");
    return text.slice(0, 120) || null;
  }
  return parsed.summary.slice(0, 120);
}
