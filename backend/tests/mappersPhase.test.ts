/**
 * Unit tests for the worker-phase allowlist in `mappers.toPhase`.
 *
 * Regression guard for M9 post-Deploy-3 followups Issue 7: the allowlist used
 * to be a hardcoded literal array that fell out of sync every time a new
 * worker phase shipped (M6p `llm_sbom`, M9 B1/B2/B4 `sbom_emit` / `sbom_ingest`
 * / `sarif_emit`, NVD addition). The fix derives the allowlist from the Zod
 * enum so the two can't drift; this test asserts that derivation actually
 * covers every enum value.
 */

import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

describe("mappers.toPhase — Zod enum coverage", () => {
  it("round-trips every value in ScanRunOutSchema.shape.current_phase", async () => {
    const { ScanRunOutSchema } = await import("../src/schemas.js");
    const { toPhase } = await import("../src/services/mappers.js");

    const enumValues = ScanRunOutSchema.shape.current_phase.unwrap().options;
    expect(enumValues.length).toBeGreaterThan(0);
    for (const value of enumValues) {
      expect(toPhase(value)).toBe(value);
    }
  });

  it("preserves null input as null", async () => {
    const { toPhase } = await import("../src/services/mappers.js");
    expect(toPhase(null)).toBeNull();
  });

  it("drops unknown phase names to null", async () => {
    const { toPhase } = await import("../src/services/mappers.js");
    expect(toPhase("not_a_phase")).toBeNull();
    expect(toPhase("")).toBeNull();
  });

  it("includes the post-M6p / M9 Stream B phases the legacy allowlist was missing", async () => {
    const { toPhase } = await import("../src/services/mappers.js");
    // The exact phases that surfaced as `null` in the closure-gate validation
    // (2026-05-22) because the hardcoded allowlist hadn't been updated.
    // Note: sbom_ingest was replaced by sbom_persist in M11 Step 1; sbom_persist
    // is in the schema enum and must round-trip cleanly.
    const phasesAddedSinceM6: ReadonlyArray<string> = [
      "llm_sbom",
      "llm_sbom_recheck",
      "sbom_persist",
      "sbom_emit",
      "nvd",
      "sarif_emit",
    ];
    for (const phase of phasesAddedSinceM6) {
      expect(toPhase(phase)).toBe(phase);
    }
  });

  it("sbom_ingest is no longer a valid phase (replaced by sbom_persist in M11)", async () => {
    const { toPhase } = await import("../src/services/mappers.js");
    expect(toPhase("sbom_ingest")).toBeNull();
  });
});
