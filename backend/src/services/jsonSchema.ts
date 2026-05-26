/**
 * M13 — JSON Schema builders for `claude -p --json-schema`.
 *
 * Produces clean structural schemas (canonical field names only — no
 * `.refine()` / `.transform()` aliases) suitable for Claude's structured-
 * output validation. The Agent SDK enforces the schema at the API
 * boundary and re-prompts the model on mismatch until it converges.
 *
 * The existing alias-aware Zod schemas in `llmSastService.ts` and
 * `llmSbomService.ts` keep their `.refine()` / `.transform()` defenses
 * for paths that bypass `--json-schema` (dry-run CLI, test fixtures,
 * legacy stream-jsonl callers).
 *
 * Phase A (v0.12.5): schemas are injected into system prompts as
 * documentation only — no CLI flag yet. Goal is to reduce first-pass
 * drift before Phase B turns on `--json-schema`.
 *
 * Phase B (v0.13.0): the rendered schemas are written to disk and
 * passed via `--json-schema <path>` to `claude -p`.
 */

import { z } from "zod";
import { zodToJsonSchema, type Options } from "zod-to-json-schema";

// ---------------------------------------------------------------------------
// Canonical-only Zod schemas (no alias fields, no refines, no transforms)
// ---------------------------------------------------------------------------

const SeverityCanonical = z.enum(["critical", "high", "medium", "low", "info"]);

/** Numeric confidence only. The string-label alias stays in llmSastService
 *  for the dry-run CLI; the schema-enforced path receives numbers. */
const ConfidenceCanonical = z.number().min(0).max(1).optional();

const SastCanonical = z.object({
  kind: z.literal("sast"),
  cwe: z.string(),
  severity: SeverityCanonical,
  cvss_vector: z.string().optional(),
  file_path: z.string(),
  start_line: z.number().int().nonnegative(),
  end_line: z.number().int().nonnegative(),
  summary: z.string(),
  confidence: ConfidenceCanonical,
  reasoning: z.string(),
});

const SastAbsenceCanonical = z.object({
  kind: z.literal("sast_absence"),
  cwe: z.string(),
  severity: SeverityCanonical,
  summary: z.string(),
  file_path: z.string(),
  start_line: z.number().int().nonnegative().optional(),
  confidence: ConfidenceCanonical,
  reasoning: z.string(),
});

const ReachabilityCallSiteCanonical = z.object({
  file_path: z.string(),
  line: z.number().int().nonnegative(),
});

const ReachabilityCanonical = z.object({
  kind: z.literal("reachability"),
  sca_issue_id: z.string(),
  reachable: z.boolean(),
  confidence: ConfidenceCanonical,
  call_sites: z.array(ReachabilityCallSiteCanonical),
  reasoning: z.string(),
});

const DetectionCompleteCanonical = z.object({
  kind: z.literal("complete"),
  sast_count: z.number().int().nonnegative().optional(),
  sast_absence_count: z.number().int().nonnegative().optional(),
  reachability_count: z.number().int().nonnegative().optional(),
  summary: z.string().optional(),
});

/**
 * Per-record union — describes the shape of ONE JSONL line the detection
 * pass emits. Used by Phase A to teach the model canonical field names
 * in the existing line-by-line streaming protocol.
 */
const DetectionRecordCanonical = z.union([
  SastCanonical,
  SastAbsenceCanonical,
  ReachabilityCanonical,
  DetectionCompleteCanonical,
]);

/**
 * Wrapper — describes the single final structured-output object that
 * `claude -p --json-schema` will return in Phase B. JSON Schema can
 * describe a JSON value but not a JSONL stream, so the wrapper is
 * what the API-side validator actually consumes.
 */
const DetectionTopCanonical = z.object({
  findings: z.array(
    z.union([SastCanonical, SastAbsenceCanonical, ReachabilityCanonical]),
  ),
  complete: DetectionCompleteCanonical,
});

const RecheckVerdictCanonical = z.object({
  id: z.string(),
  verdict: z.enum(["still_present", "fixed", "file_deleted", "duplicate_of"]),
  reasoning: z.string(),
  current_snippet: z.string().optional(),
  duplicate_of: z.string().optional(),
});

const RecheckCompleteCanonical = z.object({
  kind: z.literal("complete"),
  verified: z.number().int().nonnegative().optional(),
  still_present: z.number().int().nonnegative().optional(),
  fixed: z.number().int().nonnegative().optional(),
  file_deleted: z.number().int().nonnegative().optional(),
  duplicate_of: z.number().int().nonnegative().optional(),
});

/** Per-record union — one JSONL line emitted by the recheck pass. */
const RecheckRecordCanonical = z.union([
  RecheckVerdictCanonical,
  RecheckCompleteCanonical,
]);

/** Wrapper for Phase B `--json-schema`. */
const RecheckTopCanonical = z.object({
  verdicts: z.array(RecheckVerdictCanonical),
  complete: RecheckCompleteCanonical,
});

const EvidenceEntryCanonical = z.object({
  path: z.string(),
  line: z.number().int().nullable().optional(),
});

const KeepCanonical = z.object({
  type: z.literal("keep"),
  component_id: z.string(),
  llm_reason: z.string().optional(),
  cpe: z.string().optional(),
});

const DropCanonical = z.object({
  type: z.literal("drop"),
  component_id: z.string(),
  reason: z.string(),
  evidence_path: z.string().optional(),
});

const AddCanonical = z.object({
  type: z.literal("add"),
  name: z.string(),
  version: z.string().nullable().optional(),
  ecosystem: z.string().nullable().optional(),
  component_root: z.string(),
  evidence: z.array(EvidenceEntryCanonical),
  evidence_excerpt: z.string().optional(),
  llm_reason: z.string(),
  version_unknown: z.boolean().optional(),
  cpe: z.string().optional(),
});

/** Per-record union — one JSONL line emitted by the SBOM augmentation pass. */
const SbomRecordCanonical = z.union([
  KeepCanonical,
  DropCanonical,
  AddCanonical,
]);

/** Wrapper for Phase B `--json-schema`. */
const SbomTopCanonical = z.object({
  keeps: z.array(KeepCanonical),
  drops: z.array(DropCanonical),
  adds: z.array(AddCanonical),
});

// ---------------------------------------------------------------------------
// Build options enforcing Claude's structured-output constraints
// ---------------------------------------------------------------------------

/**
 * `$refStrategy: "none"` inlines every nested schema — Claude prohibits
 * recursive `$ref` and external URLs, and we have no shared schemas that
 * benefit from `$ref` reuse. Safer to inline everything than to map out
 * which refs Claude would accept.
 */
const CLAUDE_SCHEMA_OPTS: Partial<Options> = {
  $refStrategy: "none",
  target: "jsonSchema7",
};

export type JsonSchema = Record<string, unknown>;

// --- Phase A: per-record schemas embedded in system prompts ------------------
// Each describes the shape of ONE JSONL line. The model still emits one
// record per line in Phase A; the schema is documentation only, not yet
// enforced by `--json-schema`.

export function buildDetectionRecordSchema(): JsonSchema {
  return zodToJsonSchema(DetectionRecordCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

export function buildRecheckRecordSchema(): JsonSchema {
  return zodToJsonSchema(RecheckRecordCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

export function buildSbomRecordSchema(): JsonSchema {
  return zodToJsonSchema(SbomRecordCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

// --- Phase B: wrapper schemas passed to `claude -p --json-schema` ------------
// JSON Schema describes a single JSON value, so the API-side validator sees
// the wrapper, not the stream of records. Used only when the call site is
// switched to `--output-format json` (Phase B / v0.13.0).

export function buildDetectionSchema(): JsonSchema {
  return zodToJsonSchema(DetectionTopCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

export function buildRecheckSchema(): JsonSchema {
  return zodToJsonSchema(RecheckTopCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

export function buildSbomAugmentationSchema(): JsonSchema {
  return zodToJsonSchema(SbomTopCanonical, CLAUDE_SCHEMA_OPTS) as JsonSchema;
}

// ---------------------------------------------------------------------------
// Verification helpers (used by tests and Phase A smoke-checks)
// ---------------------------------------------------------------------------

/**
 * Walk a JSON Schema and check it matches Claude's structured-output
 * feature list. Returns a list of human-readable violations; empty
 * means the schema is compliant.
 *
 * Checks:
 *   - no `oneOf` (Zod compiles unions to `anyOf` — we want to catch
 *     regressions if a downstream config pivots that)
 *   - no `$ref` (we set `$refStrategy: "none"` so this should always be
 *     clean — guard rail)
 *   - every object has `additionalProperties: false`
 *   - no `minItems > 1` on arrays
 */
export function validateClaudeFeatures(schema: unknown, pathPrefix = "$"): string[] {
  const violations: string[] = [];
  const walk = (node: unknown, p: string): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${p}[${i}]`));
      return;
    }
    const obj = node as Record<string, unknown>;
    if ("oneOf" in obj) violations.push(`${p}: uses oneOf (must be anyOf)`);
    if ("$ref" in obj) violations.push(`${p}: uses $ref (must be inlined)`);
    if (obj.type === "object") {
      if (obj.additionalProperties !== false) {
        violations.push(
          `${p}: object missing additionalProperties:false (got ${JSON.stringify(
            obj.additionalProperties,
          )})`,
        );
      }
    }
    if (typeof obj.minItems === "number" && obj.minItems > 1) {
      violations.push(`${p}: minItems=${obj.minItems} (max 1)`);
    }
    for (const [key, value] of Object.entries(obj)) {
      walk(value, `${p}.${key}`);
    }
  };
  walk(schema, pathPrefix);
  return violations;
}

/**
 * Count optional properties across every object in the schema. Claude's
 * docs cap this at 24 per request. We surface it so a future schema
 * extension that crosses the limit fails the test rather than a scan.
 */
export function countOptionalProperties(schema: unknown): number {
  let count = 0;
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    const obj = node as Record<string, unknown>;
    if (
      obj.type === "object" &&
      typeof obj.properties === "object" &&
      obj.properties !== null
    ) {
      const propKeys = Object.keys(obj.properties as Record<string, unknown>);
      const required = Array.isArray(obj.required)
        ? new Set(obj.required as string[])
        : new Set<string>();
      count += propKeys.filter((k) => !required.has(k)).length;
    }
    for (const value of Object.values(obj)) {
      walk(value);
    }
  };
  walk(schema);
  return count;
}

/**
 * Count `anyOf` branches across the schema. Claude caps the total at 16
 * per request. Surfaces an additional safety bound.
 */
export function countAnyOfBranches(schema: unknown): number {
  let count = 0;
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.anyOf)) count += obj.anyOf.length;
    for (const value of Object.values(obj)) {
      walk(value);
    }
  };
  walk(schema);
  return count;
}
