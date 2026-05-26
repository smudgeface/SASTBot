import { describe, expect, it } from "vitest";

import {
  PARSE_ERROR_ABSOLUTE_FAILURE_COUNT,
  PARSE_ERROR_FAILURE_THRESHOLD,
  PARSE_ERROR_RAW_MAX_BYTES,
  parseErrorSeverity,
  truncateParseErrors,
} from "../src/worker.js";

describe("truncateParseErrors", () => {
  it("returns entries unchanged when raw is within the byte cap", () => {
    const input = [
      { raw: "short line", reason: "JSON parse: unexpected token" },
      { raw: "another short line", reason: "unknown record kind" },
    ];
    const result = truncateParseErrors(input);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual(input[0]);
    expect(result[1]).toEqual(input[1]);
  });

  it("truncates raw strings that exceed 2 KB", () => {
    // Generate a string that is clearly over 2048 bytes.
    const longRaw = "A".repeat(PARSE_ERROR_RAW_MAX_BYTES + 500);
    const input = [{ raw: longRaw, reason: "too long" }];
    const result = truncateParseErrors(input);
    expect(result).toHaveLength(1);
    // Encoded result must be ≤ 2048 bytes (plus suffix bytes are a tiny overrun — acceptable).
    // The truncated raw is capped at the byte boundary, then the suffix is appended.
    const truncatedText = result[0].raw;
    expect(truncatedText.endsWith("…[truncated]")).toBe(true);
    // The raw portion before the suffix must be short (≤ PARSE_ERROR_RAW_MAX_BYTES chars for ASCII).
    const withoutSuffix = truncatedText.slice(0, truncatedText.length - "…[truncated]".length);
    expect(new TextEncoder().encode(withoutSuffix).byteLength).toBeLessThanOrEqual(PARSE_ERROR_RAW_MAX_BYTES);
    // Reason is preserved.
    expect(result[0].reason).toBe("too long");
  });

  it("caps the number of entries to 5 by default", () => {
    const input = Array.from({ length: 8 }, (_, i) => ({
      raw: `line ${i}`,
      reason: `reason ${i}`,
    }));
    const result = truncateParseErrors(input);
    expect(result).toHaveLength(5);
    // Verify order is preserved.
    expect(result[0].raw).toBe("line 0");
    expect(result[4].raw).toBe("line 4");
  });

  it("respects a custom limit", () => {
    const input = Array.from({ length: 10 }, (_, i) => ({
      raw: `line ${i}`,
      reason: `reason ${i}`,
    }));
    expect(truncateParseErrors(input, 3)).toHaveLength(3);
  });

  it("returns an empty array when given an empty input", () => {
    expect(truncateParseErrors([])).toEqual([]);
  });

  it("handles multibyte UTF-8 characters at the truncation boundary", () => {
    // Build a string of 2-byte UTF-8 characters (U+0080 to U+07FF range).
    // "é" (U+00E9) is 2 bytes in UTF-8.  Repeat so total bytes > 2048.
    const multibyteChar = "é"; // 2 UTF-8 bytes
    const count = PARSE_ERROR_RAW_MAX_BYTES; // this gives 2 * 2048 = 4096 bytes
    const longRaw = multibyteChar.repeat(count);
    const input = [{ raw: longRaw, reason: "multibyte" }];
    const result = truncateParseErrors(input);
    const truncated = result[0].raw;
    // Must end with the truncation suffix.
    expect(truncated.endsWith("…[truncated]")).toBe(true);
    // The raw part before suffix must decode cleanly (no replacement characters in the middle).
    const withoutSuffix = truncated.slice(0, truncated.length - "…[truncated]".length);
    expect(withoutSuffix).not.toContain("�");
  });

  it("does not truncate a raw string at exactly the byte cap", () => {
    const exactRaw = "B".repeat(PARSE_ERROR_RAW_MAX_BYTES);
    const input = [{ raw: exactRaw, reason: "exact boundary" }];
    const result = truncateParseErrors(input);
    expect(result[0].raw).toBe(exactRaw);
    expect(result[0].raw.endsWith("…[truncated]")).toBe(false);
  });
});

describe("parseErrorSeverity — M9 followups Issue 10 + 2026-05-26 tightening", () => {
  it("escalates to error when 100% of records failed to parse", () => {
    // The closure-gate FSS scan dropped 74 / 74 SAST records this way.
    expect(parseErrorSeverity(0, 74)).toBe("error");
  });

  it("keeps info severity for low-drop scans (e.g. 1 of 100)", () => {
    expect(parseErrorSeverity(99, 1)).toBe("info");
  });

  it("keeps info severity at 5% drop (under both guards)", () => {
    // 5 < absolute guard (10) AND 5/100 = 0.05 < ratio threshold (0.25).
    expect(parseErrorSeverity(95, 5)).toBe("info");
  });

  it("escalates to error at exactly the ratio threshold (25% by default)", () => {
    // Use small totals to isolate the ratio guard from the absolute-count guard.
    // 5/20 = 0.25, exactly at threshold.
    expect(parseErrorSeverity(15, 5)).toBe("error");
  });

  it("keeps info just below the ratio threshold (~23.8%)", () => {
    // 5/21 = 0.238 — under 0.25, and 5 < absolute guard.
    expect(parseErrorSeverity(16, 5)).toBe("info");
  });

  it("escalates to error well above the ratio threshold (60%)", () => {
    expect(parseErrorSeverity(40, 60)).toBe("error");
  });

  it("keeps info severity when both counts are zero (no signal at all)", () => {
    // Caller should not emit a warning in this case, but the helper itself
    // must not classify it as error — there's nothing to be untrustworthy about.
    expect(parseErrorSeverity(0, 0)).toBe("info");
  });

  it("uses the constant PARSE_ERROR_FAILURE_THRESHOLD as the default", () => {
    // Pick a small-scale fixture where the absolute-count guard doesn't fire,
    // so we genuinely exercise the ratio threshold.  parseErrorCount strictly
    // less than PARSE_ERROR_ABSOLUTE_FAILURE_COUNT keeps the absolute guard out
    // of the way.
    const errors = PARSE_ERROR_ABSOLUTE_FAILURE_COUNT - 1; // e.g. 9
    const accepted = Math.ceil(errors / PARSE_ERROR_FAILURE_THRESHOLD) - errors;
    // accepted+errors total satisfies (errors / total) >= threshold.
    expect(parseErrorSeverity(accepted, errors)).toBe("error");
    // One fewer error keeps ratio below threshold AND keeps absolute under guard.
    expect(parseErrorSeverity(accepted + 1, errors - 1)).toBe("info");
  });

  it("respects a custom threshold override", () => {
    // Stricter threshold (10%): 5/100 drop ratio is still info AND under absolute guard.
    expect(parseErrorSeverity(95, 5, 0.1)).toBe("info");
    // 11/100: above 10% ratio and absolute count crosses 10.
    expect(parseErrorSeverity(89, 11, 0.1)).toBe("error");
  });

  // Absolute-count guard — added 2026-05-26 (GoPxL BE post-mortem).
  // The ratio-only model under-fires on large scans that drop a meaningful
  // absolute count of findings (10+ dropped is concerning even at 1% ratio).

  it("absolute-count guard: 10 dropped on a huge scan still escalates to error", () => {
    // 10/1010 = 0.0099 — well under the 0.25 ratio threshold.  The absolute
    // guard catches this so a large scan that quietly loses 10 real findings
    // is treated as degraded rather than rubber-stamped.
    expect(parseErrorSeverity(1000, 10)).toBe("error");
  });

  it("absolute-count guard: 9 dropped on a huge scan stays info", () => {
    // 9/1009 = 0.0089 — under both guards.
    expect(parseErrorSeverity(1000, 9)).toBe("info");
  });

  it("absolute-count guard: respects a custom absolute override", () => {
    // 5 dropped, threshold 0.5 (loose), absolute set to 5 — fires on absolute.
    expect(parseErrorSeverity(95, 5, 0.5, 5)).toBe("error");
    // 4 dropped under the same overrides — neither guard fires.
    expect(parseErrorSeverity(96, 4, 0.5, 5)).toBe("info");
  });

  it("absolute-count guard: 0 dropped never escalates regardless of low absolute", () => {
    // Defensive: even if the absolute guard is tuned absurdly low, 0 drops
    // can't fire it (caller is expected to short-circuit on parseErrorCount===0
    // anyway, but the helper shouldn't surprise the caller).
    expect(parseErrorSeverity(100, 0, 0.25, 1)).toBe("info");
  });
});
