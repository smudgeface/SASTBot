import { describe, expect, it } from "vitest";

import {
  buildDetectionRecordSchema,
  buildDetectionSchema,
  buildRecheckRecordSchema,
  buildRecheckSchema,
  buildSbomAugmentationSchema,
  buildSbomRecordSchema,
  validateClaudeFeatures,
  countOptionalProperties,
  countAnyOfBranches,
} from "../src/services/jsonSchema.js";

/**
 * Claude's structured-output documentation lists the schema features it
 * accepts. These tests assert every M13 schema stays inside that envelope
 * — a regression here would surface as `error_max_structured_output_retries`
 * on a real scan, costing $7-8 to diagnose. Catching it at test time is
 * the only honest gate.
 *
 * Sources verified 2026-05-26:
 *   - https://code.claude.com/docs/en/agent-sdk/structured-outputs
 *   - https://code.claude.com/docs/en/cli-reference
 *
 * Two schema shapes per phase:
 *   - Record schema: per-JSONL-line union, used by Phase A prompt embedding.
 *   - Top-level schema: wrapper for Phase B `--json-schema`. JSON Schema
 *     describes a single value, not a stream — the wrapper is the value the
 *     API validator sees.
 */

const ALL_BUILDERS = [
  ["detection record", buildDetectionRecordSchema],
  ["recheck record", buildRecheckRecordSchema],
  ["sbom record", buildSbomRecordSchema],
  ["detection top-level", buildDetectionSchema],
  ["recheck top-level", buildRecheckSchema],
  ["sbom top-level", buildSbomAugmentationSchema],
] as const;

describe("jsonSchema builders — Claude feature compliance", () => {
  for (const [name, build] of ALL_BUILDERS) {
    describe(name, () => {
      it("produces a schema with zero Claude-feature violations", () => {
        const schema = build();
        const violations = validateClaudeFeatures(schema);
        expect(violations).toEqual([]);
      });

      it("never emits oneOf", () => {
        expect(JSON.stringify(build())).not.toContain('"oneOf"');
      });

      it("inlines all subschemas (no $ref)", () => {
        expect(JSON.stringify(build())).not.toContain('"$ref"');
      });

      it("sets additionalProperties:false on every object", () => {
        const schema = build();
        expect(countObjectsAllowingAdditional(schema)).toBe(0);
      });

      it("stays under Claude's complexity caps", () => {
        const schema = build();
        // Docs: max 24 optional parameters total across the request.
        expect(countOptionalProperties(schema)).toBeLessThanOrEqual(24);
        // Docs: max 16 anyOf branches across the request.
        expect(countAnyOfBranches(schema)).toBeLessThanOrEqual(16);
      });
    });
  }
});

describe("jsonSchema — Phase A per-record canonicalization", () => {
  it("detection record is an anyOf over the record kinds (sast, sast_absence, reachability, complete)", () => {
    const schema = buildDetectionRecordSchema();
    const branches = schema.anyOf as Array<Record<string, unknown>>;
    expect(Array.isArray(branches)).toBe(true);
    const kinds = branches.map((b) => {
      const props = b.properties as Record<string, unknown>;
      const kindProp = props.kind as Record<string, unknown>;
      return kindProp.const as string;
    });
    expect(kinds.sort()).toEqual(["complete", "reachability", "sast", "sast_absence"]);
  });

  it("detection record SAST branch requires canonical names (cwe, file_path, summary, reasoning)", () => {
    const schema = buildDetectionRecordSchema();
    const sast = pickAnyOfBranchByConst(schema, "kind", "sast");
    const required = sast.required as string[];
    expect(required).toContain("cwe");
    expect(required).toContain("file_path");
    expect(required).toContain("summary");
    expect(required).toContain("reasoning");
    // Aliases must NOT appear — they live in the legacy Zod schemas only.
    const props = sast.properties as Record<string, unknown>;
    expect(props).not.toHaveProperty("cwe_id");
    expect(props).not.toHaveProperty("file");
    expect(props).not.toHaveProperty("title");
    expect(props).not.toHaveProperty("description");
  });

  it("detection record reachability uses kind=reachability (not sca_reachability)", () => {
    const schema = buildDetectionRecordSchema();
    const reach = pickAnyOfBranchByConst(schema, "kind", "reachability");
    const kindProp = (reach.properties as Record<string, unknown>).kind as Record<string, unknown>;
    expect(kindProp.const).toBe("reachability");
  });

  it("detection record confidence is a number 0..1, not a string label", () => {
    const schema = buildDetectionRecordSchema();
    const sast = pickAnyOfBranchByConst(schema, "kind", "sast");
    const confidence = (sast.properties as Record<string, unknown>).confidence as Record<string, unknown>;
    expect(confidence.type).toBe("number");
    expect(confidence.minimum).toBe(0);
    expect(confidence.maximum).toBe(1);
  });

  it("recheck record is an anyOf over (verdict, complete)", () => {
    const schema = buildRecheckRecordSchema();
    const branches = schema.anyOf as Array<Record<string, unknown>>;
    expect(branches.length).toBe(2);
  });

  it("sbom record is an anyOf over (keep, drop, add)", () => {
    const schema = buildSbomRecordSchema();
    const branches = schema.anyOf as Array<Record<string, unknown>>;
    const types = branches.map((b) => {
      const props = b.properties as Record<string, unknown>;
      const typeProp = props.type as Record<string, unknown>;
      return typeProp.const as string;
    });
    expect(types.sort()).toEqual(["add", "drop", "keep"]);
  });

  it("sbom add branch requires component_root + evidence (no legacy aliases)", () => {
    const schema = buildSbomRecordSchema();
    const add = pickAnyOfBranchByConst(schema, "type", "add");
    const required = add.required as string[];
    expect(required).toContain("component_root");
    expect(required).toContain("evidence");
    expect(required).toContain("llm_reason");
    const props = add.properties as Record<string, unknown>;
    expect(props).not.toHaveProperty("evidence_paths");
    expect(props).not.toHaveProperty("evidence_path");
  });
});

describe("jsonSchema — Phase B wrapper shape", () => {
  it("detection wrapper requires findings[] and complete", () => {
    const schema = buildDetectionSchema();
    expect(schema.type).toBe("object");
    expect(schema.required).toEqual(expect.arrayContaining(["findings", "complete"]));
  });

  it("recheck wrapper requires verdicts[] and complete", () => {
    const schema = buildRecheckSchema();
    expect(schema.required).toEqual(expect.arrayContaining(["verdicts", "complete"]));
  });

  it("sbom wrapper requires keeps[], drops[], adds[]", () => {
    const schema = buildSbomAugmentationSchema();
    expect(schema.required).toEqual(expect.arrayContaining(["keeps", "drops", "adds"]));
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countObjectsAllowingAdditional(node: unknown): number {
  let count = 0;
  const walk = (n: unknown): void => {
    if (n === null || typeof n !== "object") return;
    if (Array.isArray(n)) {
      n.forEach(walk);
      return;
    }
    const obj = n as Record<string, unknown>;
    if (obj.type === "object" && obj.additionalProperties !== false) {
      count++;
    }
    for (const v of Object.values(obj)) walk(v);
  };
  walk(node);
  return count;
}

function pickAnyOfBranchByConst(
  schema: Record<string, unknown>,
  discriminatorProp: string,
  constValue: string,
): Record<string, unknown> {
  const branches = schema.anyOf as Array<Record<string, unknown>>;
  for (const branch of branches) {
    const props = branch.properties as Record<string, unknown>;
    const disc = props[discriminatorProp] as Record<string, unknown> | undefined;
    if (disc && disc.const === constValue) return branch;
  }
  throw new Error(`No anyOf branch with ${discriminatorProp}=${constValue}`);
}
