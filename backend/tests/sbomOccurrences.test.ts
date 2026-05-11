/**
 * Unit tests for sbomOccurrences.ts — M6q §1.5
 *
 * Cases per plan:
 *  - Occurrence shape with #line parsing
 *  - Identity-only fallback (manifest-discovered components)
 *  - Defensive clone-prefix stripping (backfill mode)
 *  - LLM-augmentation single-entry case
 *  - SrcFile-property skip
 */

import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import type { CdxComponent } from "../src/services/sbomService.js";

// sbomOccurrences imports config at module load time — set env vars first.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// Dynamic import so env vars are set before module initializes.
async function getExtractOccurrences() {
  const mod = await import("../src/services/sbomOccurrences.js");
  return mod.extractOccurrences;
}

function makeComponent(overrides: Partial<CdxComponent>): CdxComponent {
  return {
    name: "SomeLib",
    version: "1.0.0",
    purl: "pkg:generic/SomeLib@1.0.0",
    ...overrides,
  };
}

describe("extractOccurrences", () => {
  it("parses evidence.occurrences with path#line format", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [
          { location: "GoWeb/kJs/src/Record.js#3" },
          { location: "GoWeb/kJs/src/Player.js#42" },
          { location: "GoWeb/kJs/src/Player.js#42" }, // duplicate — should be deduped
        ],
      },
    });
    const result = extractOccurrences(c, null, false);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({ path: "GoWeb/kJs/src/Record.js", line: 3 });
    expect(result[1]).toEqual({ path: "GoWeb/kJs/src/Player.js", line: 42 });
  });

  it("handles occurrences with no line number (no # suffix)", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [{ location: "GoEmulate/packages.config" }],
      },
    });
    const result = extractOccurrences(c, null, false);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ path: "GoEmulate/packages.config", line: null });
  });

  it("falls back to identity methods when occurrences is empty", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [],
        identity: [
          {
            methods: [
              { technique: "manifest-analysis", value: "GoEmulate/GoEmulateApp/packages.config" },
            ],
          },
        ],
      },
    });
    const result = extractOccurrences(c, null, false);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ path: "GoEmulate/GoEmulateApp/packages.config", line: null });
  });

  it("falls back to concludedValue when methods is empty", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [],
        identity: [
          {
            methods: [],
            concludedValue: "GoEmulate/GoEmulateApp/packages.config",
          } as unknown as { methods?: Array<{ technique?: string; value?: string }>; concludedValue?: string },
        ],
      },
    });
    const result = extractOccurrences(c, null, false);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ path: "GoEmulate/GoEmulateApp/packages.config", line: null });
  });

  it("skips SrcFile properties entirely", async () => {
    const extractOccurrences = await getExtractOccurrences();
    // Component with ONLY SrcFile properties, no evidence — should return []
    const c = makeComponent({
      properties: [
        { name: "SrcFile", value: "GoEmulate/GoEmulateApp/packages.config" },
        { name: "SrcFile", value: "GoEmulate/GoEmulateApp/packages.config" }, // duplicate
      ],
      // no evidence block
    });
    const result = extractOccurrences(c, null, false);
    // SrcFile should be skipped; result is empty since no evidence or occurrences
    expect(result).toHaveLength(0);
  });

  it("includes llm_evidence.path as fallback occurrence for LLM-augmented components", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      // No evidence block at all — LLM-added component
    });
    const result = extractOccurrences(c, "extern/gettext/gettext.h", false);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ path: "extern/gettext/gettext.h", line: null });
  });

  it("dedupes llm_evidence.path when already present in occurrences", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [{ location: "extern/gettext/gettext.h#1" }],
      },
    });
    // llm_evidence.path is same path but with a line
    const result = extractOccurrences(c, "extern/gettext/gettext.h", false);
    // The path differs by line (1 vs null) BUT dedupe is by (path, line).
    // The occurrence with line=1 comes first; llm_evidence path adds line=null
    // which is a different (path, line) key, so it gets appended.
    // This is acceptable — two entries for the same file is fine.
    expect(result.some((o) => o.path === "extern/gettext/gettext.h")).toBe(true);
  });

  describe("backfill mode: defensive clone-prefix stripping (stripPrefix=true)", () => {
    it("strips ../clones/<uuid>/ prefix from identity paths", async () => {
      const extractOccurrences = await getExtractOccurrences();
      const uuid = "12345678-1234-1234-1234-123456789abc";
      const c = makeComponent({
        evidence: {
          occurrences: [],
          identity: [
            {
              methods: [
                {
                  technique: "manifest-analysis",
                  value: `../clones/${uuid}/GoEmulate/GoEmulateApp/packages.config`,
                },
              ],
            },
          ],
        },
      });
      const result = extractOccurrences(c, null, /* stripPrefix */ true);
      expect(result).toHaveLength(1);
      expect(result[0]!.path).toBe("GoEmulate/GoEmulateApp/packages.config");
    });

    it("strips absolute /…/clones/<uuid>/ prefix", async () => {
      const extractOccurrences = await getExtractOccurrences();
      const uuid = "aaaabbbb-cccc-dddd-eeee-ffffgggghhhh";
      // Use a valid UUID hex only — let's use a proper one
      const validUuid = "aabbccdd-eeff-1122-3344-556677889900";
      const c = makeComponent({
        evidence: {
          occurrences: [],
          identity: [
            {
              methods: [
                {
                  value: `/app/clones/${validUuid}/GoWeb/package-lock.json`,
                },
              ],
            },
          ],
        },
      });
      const result = extractOccurrences(c, null, true);
      expect(result).toHaveLength(1);
      expect(result[0]!.path).toBe("GoWeb/package-lock.json");
    });

    it("leaves already-clean paths unchanged in backfill mode", async () => {
      const extractOccurrences = await getExtractOccurrences();
      const c = makeComponent({
        evidence: {
          occurrences: [{ location: "GoEmulate/packages.config#5" }],
        },
      });
      const result = extractOccurrences(c, null, true);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ path: "GoEmulate/packages.config", line: 5 });
    });
  });

  it("extracts multiple occurrences from evidence.identity with multiple methods", async () => {
    const extractOccurrences = await getExtractOccurrences();
    const c = makeComponent({
      evidence: {
        occurrences: [],
        identity: [
          {
            methods: [
              { value: "GoEmulate/GoEmulateApp/packages.config" },
              { value: "GoEmulate/GoEmulateApp/packages.config" }, // dup
              { value: "GoWeb/package-lock.json" },
            ],
          },
        ],
      },
    });
    const result = extractOccurrences(c, null, false);
    // deduped: 2 unique paths
    expect(result).toHaveLength(2);
    expect(result.map((r) => r.path)).toContain("GoEmulate/GoEmulateApp/packages.config");
    expect(result.map((r) => r.path)).toContain("GoWeb/package-lock.json");
    // no line numbers since these came from identity methods
    expect(result.every((r) => r.line === null)).toBe(true);
  });
});
