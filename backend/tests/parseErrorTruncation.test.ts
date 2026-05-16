import { describe, expect, it } from "vitest";

import { truncateParseErrors, PARSE_ERROR_RAW_MAX_BYTES } from "../src/worker.js";

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
