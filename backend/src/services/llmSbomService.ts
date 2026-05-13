/**
 * M6p Stage 2 — LLM SBOM augmentation pass.
 *
 * Runs between cdxgen + Stage-1 post-processing and OSV. Spawns `claude -p`
 * with the cleaned Stage-1 SBOM written to a tmp file, asks the model to:
 *   - confirm (keep) or reject (drop) each cdxgen component
 *   - add components it found in vendored directories that cdxgen missed
 *
 * Output protocol: JSON-Lines, each line one of:
 *   {"type":"keep","component_id":"..."}
 *   {"type":"drop","component_id":"...","reason":"...","evidence_path":"..."}
 *   {"type":"add","name":"...","version":"...","ecosystem":"...",
 *    "evidence_path":"...","evidence_excerpt":"...","llm_reason":"..."}
 *
 * The service returns a structured result; the worker applies the augmentation
 * to the in-memory component list before calling persistComponents.
 *
 * Mirrors llmSastService.ts as closely as possible — same spawnClaudeAndStream
 * helper, same error-handling patterns, same token-usage tracking.
 */

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import { decodeCredential } from "./credentialService.js";
import { getOrCreateSettings } from "./settingsService.js";
import { loadPrompt } from "./promptLoader.js";
import type { CdxComponent } from "./sbomService.js";

const logger = pino({ level: loadConfig().logLevel, name: "llmSbomService" });

// Matches the `claudeuser` row created in docker/backend.Dockerfile.
const CLAUDE_UID = 1001;
const CLAUDE_GID = 1001;

// ---------------------------------------------------------------------------
// Output record schemas (one per type in the JSON-Lines output protocol)
// ---------------------------------------------------------------------------

const KeepRecord = z.object({
  type: z.literal("keep"),
  component_id: z.string(),
  /** Optional one-line rationale. Stored as llmReason in llmEvidence. */
  llm_reason: z.string().optional(),
  /** Optional CPE 2.3 string for precise NVD lookup (e.g. "cpe:2.3:a:zlib:zlib:1.2.6:*:*:*:*:*:*:*"). */
  cpe: z.string().optional(),
});
export type KeepRecord = z.infer<typeof KeepRecord>;

const DropRecord = z.object({
  type: z.literal("drop"),
  component_id: z.string(),
  reason: z.string(),
  evidence_path: z.string().optional(),
});
export type DropRecord = z.infer<typeof DropRecord>;

const AddRecord = z.object({
  type: z.literal("add"),
  name: z.string(),
  version: z.string().nullable().optional(),
  /** Ecosystem slug: "npm" | "pypi" | "maven" | "nuget" | "generic" | etc. */
  ecosystem: z.string().nullable().optional(),
  evidence_path: z.string(),
  evidence_excerpt: z.string().optional(),
  llm_reason: z.string(),
  /** When true the version field could not be determined from the source. */
  version_unknown: z.boolean().optional(),
  /** Optional CPE 2.3 string for precise NVD lookup. */
  cpe: z.string().optional(),
});
export type AddRecord = z.infer<typeof AddRecord>;

const AugmentationRecord = z.discriminatedUnion("type", [
  KeepRecord,
  DropRecord,
  AddRecord,
]);
export type AugmentationRecord = z.infer<typeof AugmentationRecord>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
  estimatedUsdCost: number | null;
  requestCount: number;
}

export interface ParseError {
  raw: string;
  reason: string;
}

export interface RunSbomAugmentationInput {
  scanRunId: string;
  /** Absolute path to the scope working directory (the clone root or sub-path). */
  scopeDir: string;
  /** Repo-rooted scope path, e.g. "/" or "/GoWeb". */
  scopePath: string;
  /** Stage-1-cleaned component list. Passed so we can write the SBOM to disk. */
  components: CdxComponent[];
  firstPartyNamespaces: string[];
  vendoredDirs: string[];
  tokenBudget: number;
  effortLevel: string;
  orgId: string | null;
  onProgress?: (usage: TokenUsage) => void;
}

export interface RunSbomAugmentationResult {
  records: AugmentationRecord[];
  parseErrors: ParseError[];
  exitCode: number | null;
  durationMs: number;
  usage: TokenUsage;
}

// ---------------------------------------------------------------------------
// LLM config resolution (mirrors llmSastService)
// ---------------------------------------------------------------------------

async function resolveLlmConfig(orgId: string | null): Promise<{
  baseUrl: string;
  modelName: string;
  apiKey: string;
}> {
  const settings = await getOrCreateSettings(orgId);
  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    throw new Error(
      "LLM SBOM augmentation requires AppSettings.llmBaseUrl, llmModel, and llmCredentialId to be configured.",
    );
  }
  if (settings.llmApiFormat && settings.llmApiFormat !== "anthropic-messages") {
    throw new Error(
      `LLM SBOM augmentation requires llmApiFormat='anthropic-messages'; got '${settings.llmApiFormat}'.`,
    );
  }
  const credential = await decodeCredential(settings.llmCredentialId);
  if (credential.kind !== "llm_api_key") {
    throw new Error(
      `LLM SBOM augmentation expects an llm_api_key credential; got ${credential.kind}.`,
    );
  }
  return {
    baseUrl: settings.llmBaseUrl,
    modelName: settings.llmModel,
    apiKey: credential.value,
  };
}

// ---------------------------------------------------------------------------
// Tmp directory setup
// ---------------------------------------------------------------------------

async function ensureSbomTmpDir(
  scanRunId: string,
): Promise<{ tmpDir: string; claudeHome: string }> {
  const tmpDir = `/tmp/sastbot-sbom-${scanRunId}`;
  const claudeHome = path.join(tmpDir, "home");
  await fs.mkdir(tmpDir, { recursive: true, mode: 0o755 });
  await fs.mkdir(claudeHome, { recursive: true, mode: 0o755 });
  await fs.chown(claudeHome, CLAUDE_UID, CLAUDE_GID).catch(() => {
    /* non-fatal on filesystems without chown support */
  });
  return { tmpDir, claudeHome };
}

// ---------------------------------------------------------------------------
// claude-p orchestrator (mirrors spawnClaudeAndStream in llmSastService)
// ---------------------------------------------------------------------------

interface SpawnClaudeInput {
  scanRunId: string;
  scopeDir: string;
  systemPrompt: string;
  userPrompt: string;
  modelName: string;
  apiKey: string;
  baseUrl: string;
  claudeHome: string;
  effortLevel: string;
  onLine: (line: string) => void;
  onProgress?: (usage: TokenUsage) => void;
}

interface SpawnClaudeResult {
  exitCode: number | null;
  usage: TokenUsage;
}

async function spawnClaudeAndStream(
  input: SpawnClaudeInput,
): Promise<SpawnClaudeResult> {
  const args = [
    "-p",
    input.userPrompt,
    "--model",
    input.modelName,
    "--effort",
    input.effortLevel,
    "--allowed-tools",
    "Bash Read Glob Grep",
    "--permission-mode",
    "bypassPermissions",
    "--output-format",
    "stream-json",
    "--verbose",
    "--append-system-prompt",
    input.systemPrompt,
  ];

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ANTHROPIC_API_KEY: input.apiKey,
    ANTHROPIC_BASE_URL: input.baseUrl,
    HOME: input.claudeHome,
    USER: "claudeuser",
  };

  const usage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
    estimatedUsdCost: null,
    requestCount: 0,
  };

  const exitCode: number | null = await new Promise((resolve, reject) => {
    const proc = spawn("claude", args, {
      cwd: input.scopeDir,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
      uid: CLAUDE_UID,
      gid: CLAUDE_GID,
    });

    let stdoutBuf = "";
    let stderrBuf = "";
    let assistantTextBuf = "";

    const flushAssistantLines = (final: boolean): void => {
      const lines = assistantTextBuf.split("\n");
      const tail = final ? "" : (lines.pop() ?? "");
      assistantTextBuf = tail;
      for (const raw of lines) {
        const trimmed = raw.trim();
        if (!trimmed) continue;
        input.onLine(trimmed);
      }
    };

    const handleStreamEvent = (event: unknown): void => {
      if (!event || typeof event !== "object" || !("type" in event)) return;
      const t = (event as { type: string }).type;

      if (t === "assistant") {
        const msg = (event as {
          message?: {
            content?: Array<{ type?: string; text?: string }>;
            usage?: {
              input_tokens?: number;
              output_tokens?: number;
              cache_read_input_tokens?: number;
              cache_creation_input_tokens?: number;
            };
          };
        }).message;
        const u = msg?.usage ?? {};
        usage.inputTokens += u.input_tokens ?? 0;
        usage.outputTokens += u.output_tokens ?? 0;
        usage.cacheReadInputTokens += u.cache_read_input_tokens ?? 0;
        usage.cacheCreationInputTokens += u.cache_creation_input_tokens ?? 0;
        const content = msg?.content ?? [];
        for (const block of content) {
          if (block.type === "text" && typeof block.text === "string") {
            assistantTextBuf += block.text;
          }
        }
        usage.requestCount += 1;
        flushAssistantLines(false);
        if (input.onProgress) input.onProgress(usage);
        return;
      }

      if (t === "result") {
        const ev = event as {
          usage?: {
            input_tokens?: number;
            output_tokens?: number;
            cache_read_input_tokens?: number;
            cache_creation_input_tokens?: number;
          };
          total_cost_usd?: number;
          cost_usd?: number;
        };
        const u = ev.usage ?? {};
        usage.inputTokens = u.input_tokens ?? 0;
        usage.outputTokens = u.output_tokens ?? 0;
        usage.cacheReadInputTokens = u.cache_read_input_tokens ?? 0;
        usage.cacheCreationInputTokens = u.cache_creation_input_tokens ?? 0;
        usage.estimatedUsdCost = ev.total_cost_usd ?? ev.cost_usd ?? null;
      }
    };

    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => {
      stdoutBuf += chunk;
      const lines = stdoutBuf.split("\n");
      stdoutBuf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          handleStreamEvent(JSON.parse(trimmed));
        } catch (err) {
          logger.debug(
            { line: trimmed.slice(0, 200), err: (err as Error).message },
            "[llmSbomService] non-JSON stream line",
          );
        }
      }
    });

    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      stderrBuf += chunk;
    });

    proc.on("error", (err) => {
      logger.error({ err: err.message }, "[llmSbomService] claude spawn error");
      reject(err);
    });

    proc.on("close", (code) => {
      flushAssistantLines(true);
      if (stderrBuf.trim().length > 0) {
        logger.info(
          { stderr: stderrBuf.slice(0, 2000) },
          "[llmSbomService] claude stderr",
        );
      }
      resolve(code);
    });
  });

  return { exitCode, usage };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Runs the LLM SBOM augmentation pass.
 *
 * Writes the Stage-1-cleaned SBOM to a tmp file, spawns claude-p, parses the
 * JSON-Lines output. Returns structured records; does NOT persist to DB —
 * the caller (worker.ts) does that after applying the records to the
 * component list.
 */
export async function runSbomAugmentation(
  input: RunSbomAugmentationInput,
): Promise<RunSbomAugmentationResult> {
  const startedAt = Date.now();
  const { baseUrl, modelName, apiKey } = await resolveLlmConfig(input.orgId);
  const { tmpDir, claudeHome } = await ensureSbomTmpDir(input.scanRunId);

  // Write Stage-1 SBOM to a tmp file so the prompt can tell the LLM to Read it
  // without inlining potentially hundreds of components in the prompt text.
  const sbomFilePath = path.join(tmpDir, "cdxgen-sbom.json");
  const sbomPayload = buildSbomPayload(input.components);
  await fs.writeFile(sbomFilePath, JSON.stringify(sbomPayload, null, 2), {
    encoding: "utf8",
    mode: 0o644,
  });

  const firstPartyBlock =
    input.firstPartyNamespaces.length > 0
      ? input.firstPartyNamespaces.map((ns) => `  - ${ns}`).join("\n")
      : "  (none — no first-party namespaces configured for this repo)";

  const vendoredDirsBlock =
    input.vendoredDirs.length > 0
      ? input.vendoredDirs.map((d) => `  - ${d}`).join("\n")
      : "  (none configured)";

  const systemPrompt = loadPrompt("sbom_system", {});
  const userPrompt = loadPrompt("sbom_augmentation", {
    SBOM_FILE: sbomFilePath,
    SCOPE_PATH: input.scopeDir,
    SCOPE_PATH_LABEL: input.scopePath === "/" || input.scopePath === "" ? "/" : input.scopePath,
    FIRST_PARTY_NAMESPACES: firstPartyBlock,
    VENDORED_DIRS: vendoredDirsBlock,
    TOKEN_BUDGET: String(input.tokenBudget),
  });

  logger.info(
    {
      scanRunId: input.scanRunId,
      scopeDir: input.scopeDir,
      componentCount: input.components.length,
      firstPartyNamespaces: input.firstPartyNamespaces,
      vendoredDirs: input.vendoredDirs,
      tokenBudget: input.tokenBudget,
      model: modelName,
      baseUrl,
    },
    "[llmSbomService] starting augmentation",
  );

  const records: AugmentationRecord[] = [];
  const parseErrors: ParseError[] = [];

  const { exitCode, usage } = await spawnClaudeAndStream({
    scanRunId: input.scanRunId,
    scopeDir: input.scopeDir,
    systemPrompt,
    userPrompt,
    modelName,
    apiKey,
    baseUrl,
    claudeHome,
    effortLevel: input.effortLevel,
    onProgress: input.onProgress,
    onLine: (line) => {
      if (!line.startsWith("{")) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        parseErrors.push({
          raw: line,
          reason: `JSON parse: ${(err as Error).message}`,
        });
        return;
      }
      const result = AugmentationRecord.safeParse(parsed);
      if (!result.success) {
        parseErrors.push({
          raw: line,
          reason: `schema: ${result.error.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")}`,
        });
        return;
      }
      records.push(result.data);
    },
  });

  const durationMs = Date.now() - startedAt;
  logger.info(
    {
      scanRunId: input.scanRunId,
      exitCode,
      durationMs,
      recordCount: records.length,
      parseErrorCount: parseErrors.length,
      keeps: records.filter((r) => r.type === "keep").length,
      drops: records.filter((r) => r.type === "drop").length,
      adds: records.filter((r) => r.type === "add").length,
      usage,
    },
    "[llmSbomService] augmentation finished",
  );

  return { records, parseErrors, exitCode, durationMs, usage };
}

/**
 * Build a JSON payload from the cleaned component list that's suitable for
 * the LLM to read. We include a `component_id` field (the canonical key the
 * LLM should use in its keep/drop records) alongside the standard fields.
 */
function buildSbomPayload(components: CdxComponent[]): {
  components: Array<{
    component_id: string;
    name: string;
    version: string | null;
    ecosystem: string | null;
    purl: string | null;
    licenses: string[];
  }>;
} {
  return {
    components: components.map((c) => {
      const ecosystem = extractEcosystemFromPurl(c.purl);
      return {
        component_id: canonicalKeyFor(c, ecosystem),
        name: canonicalKeyFor(c, ecosystem), // same for display
        version: c.version ?? null,
        ecosystem,
        purl: c.purl ?? null,
        licenses: extractLicenseStrings(c.licenses),
      };
    }),
  };
}

function extractEcosystemFromPurl(purl: string | undefined): string | null {
  if (!purl) return null;
  const m = purl.match(/^pkg:([^/]+)\//);
  return m ? m[1] : null;
}

function canonicalKeyFor(c: CdxComponent, ecosystem: string | null): string {
  const name = c.name ?? "unknown";
  if (!c.group) return name;
  const sep = ecosystem === "maven" ? ":" : "/";
  return `${c.group}${sep}${name}`;
}

function extractLicenseStrings(
  entries: Array<{ license?: { id?: string; name?: string }; expression?: string }> | undefined,
): string[] {
  if (!entries) return [];
  return entries
    .map((e) => e.license?.id ?? e.license?.name ?? e.expression ?? null)
    .filter((l): l is string => l !== null);
}

// ---------------------------------------------------------------------------
// Augmentation application (pure function — called by worker.ts)
// ---------------------------------------------------------------------------

export interface LlmEvidence {
  path: string;
  excerpt: string | null;
  llmReason: string;
}

export interface SbomAugmentationApplied {
  /** Final list of CdxComponents after keep/drop/add. */
  components: CdxComponent[];
  /** Map from canonical component_id → evidence (for persisting llmEvidence). */
  evidenceMap: Map<string, LlmEvidence>;
  /** Map from canonical component_id → CPE 2.3 string (for persistAugmentedComponents). */
  cpeMap: Map<string, string>;
}

/**
 * Apply augmentation records to the Stage-1 component list.
 *
 * Rules:
 * - `keep`: preserve the component as-is (optionally with llmEvidence).
 * - `drop`: remove the component from the output. Log the reason.
 * - `add`:  synthesise a CdxComponent from the LLM fields and append to the
 *           output. Deduped by canonical key — if the key already exists
 *           (e.g. LLM adds something Stage 1 kept), skip the add.
 *
 * Components not mentioned in any record are kept as-is (conservative bias:
 * silence != rejection). This ensures the LLM only needs to actively act on
 * items it's confident about, not enumerate every component.
 */
export function applySbomAugmentation(
  components: CdxComponent[],
  result: RunSbomAugmentationResult,
): SbomAugmentationApplied {
  const { records } = result;

  // Build fast lookup maps keyed by component_id (canonical name).
  const dropSet = new Set<string>();
  const evidenceMap = new Map<string, LlmEvidence>();
  const cpeMap = new Map<string, string>();

  for (const r of records) {
    if (r.type === "drop") {
      dropSet.add(r.component_id);
      logger.info(
        { component_id: r.component_id, reason: r.reason },
        "[llmSbomService] dropping component",
      );
    } else if (r.type === "keep") {
      if (r.llm_reason) {
        // Only store evidence when the LLM supplied a rationale.
        evidenceMap.set(r.component_id, {
          path: "",
          excerpt: null,
          llmReason: r.llm_reason,
        });
      }
      if (r.cpe) {
        cpeMap.set(r.component_id, r.cpe);
      }
    } else if (r.type === "add") {
      evidenceMap.set(r.name, {
        path: r.evidence_path,
        excerpt: r.evidence_excerpt ?? null,
        llmReason: r.llm_reason,
      });
      if (r.cpe) {
        cpeMap.set(r.name, r.cpe);
      }
    }
  }

  // Build index of existing canonical keys so we can dedupe adds.
  const existingKeys = new Set<string>(
    components.map((c) => canonicalKeyFor(c, extractEcosystemFromPurl(c.purl))),
  );

  // Apply drops + collect survivors.
  const survivors = components.filter((c) => {
    const key = canonicalKeyFor(c, extractEcosystemFromPurl(c.purl));
    return !dropSet.has(key);
  });

  // Synthesise added components.
  const addRecords = records.filter((r): r is AddRecord => r.type === "add");
  const synthesised: CdxComponent[] = [];
  for (const r of addRecords) {
    if (existingKeys.has(r.name)) {
      logger.debug(
        { name: r.name },
        "[llmSbomService] skipping add — component already exists",
      );
      continue;
    }
    const eco = r.ecosystem ?? "generic";
    const purl = `pkg:${eco}/${encodeURIComponent(r.name)}${r.version ? `@${encodeURIComponent(r.version)}` : ""}`;
    synthesised.push({
      name: r.name,
      version: r.version ?? undefined,
      purl,
      // No group / licenses for LLM-added components (not yet known).
      discoveryMethod: "llm_augmentation",
    } as CdxComponent & { discoveryMethod: string });
    existingKeys.add(r.name);
    logger.info(
      { name: r.name, version: r.version, evidencePath: r.evidence_path },
      "[llmSbomService] adding component",
    );
  }

  return {
    components: [...survivors, ...synthesised],
    evidenceMap,
    cpeMap,
  };
}

/**
 * Idempotent cleanup of the per-scan SBOM tmp directory.
 */
export async function cleanupSbomTmp(scanRunId: string): Promise<void> {
  const tmpDir = `/tmp/sastbot-sbom-${scanRunId}`;
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
}
