/**
 * Unit tests for the robust JSON-object stream extractor used by all three
 * LLM stream parsers (SAST detection, SAST recheck, SBOM augmentation,
 * SBOM recheck). The line-split predecessor silently lost any record the
 * LLM concatenated on a single line — on the 2026-05-22 FSS scan that meant
 * 5 of the 16 unparseable records were actual SAST findings dropped between
 * the model's mouth and the database.
 *
 * Cases are anchored to the real failure modes seen on that scan; every
 * `it()` documents what concrete LLM behaviour it pins.
 */
import { describe, expect, it } from "vitest";
import { extractJsonObjects } from "../src/services/llmSastService.js";

describe("extractJsonObjects", () => {
  it("extracts a single object", () => {
    const { objects, rest } = extractJsonObjects('{"kind":"sast","cwe":"CWE-22"}');
    expect(objects).toEqual(['{"kind":"sast","cwe":"CWE-22"}']);
    expect(rest).toBe("");
  });

  it("extracts two objects separated by a newline", () => {
    const buf = '{"a":1}\n{"b":2}\n';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toEqual(['{"a":1}', '{"b":2}']);
    expect(rest).toBe("");
  });

  it("extracts two objects concatenated on the SAME LINE (the 2026-05-22 FSS bug)", () => {
    // This is exactly the shape that lost 5 SAST findings on the prior run.
    const buf = '{"kind":"sast","cwe":"CWE-78","start_line":54,"end_line":70}{"kind":"sast","cwe":"CWE-345","start_line":307,"end_line":316}';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toHaveLength(2);
    expect(JSON.parse(objects[0])).toMatchObject({ kind: "sast", cwe: "CWE-78" });
    expect(JSON.parse(objects[1])).toMatchObject({ kind: "sast", cwe: "CWE-345" });
    expect(rest).toBe("");
  });

  it("does not count braces inside string literals", () => {
    // Reasoning fields routinely contain `{` and `}` characters.
    const buf = '{"reasoning":"function uses { malloc(size) } pattern"}';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toEqual([buf]);
    expect(rest).toBe("");
  });

  it("respects escaped quotes inside strings", () => {
    const buf = '{"summary":"calls \\"system\\" with user input"}';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toEqual([buf]);
    expect(rest).toBe("");
    expect(JSON.parse(objects[0])).toMatchObject({ summary: 'calls "system" with user input' });
  });

  it("carries forward a partial trailing object as rest", () => {
    const buf = '{"a":1}\n{"b":';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toEqual(['{"a":1}']);
    expect(rest).toBe('{"b":');
  });

  it("preserves a partial object across two flush calls", () => {
    // Simulates the LLM emitting a record that spans two chunks.
    const chunk1 = '{"kind":"sast","cwe":"CWE-22","file_path":"a.cpp","start_l';
    const chunk2 = 'ine":1,"end_line":2,"summary":"x","confidence":0.9}';
    let buf = "";
    buf += chunk1;
    const r1 = extractJsonObjects(buf);
    expect(r1.objects).toHaveLength(0);
    expect(r1.rest).toBe(chunk1);

    buf = r1.rest + chunk2;
    const r2 = extractJsonObjects(buf);
    expect(r2.objects).toHaveLength(1);
    expect(JSON.parse(r2.objects[0])).toMatchObject({
      kind: "sast",
      cwe: "CWE-22",
      start_line: 1,
      end_line: 2,
    });
    expect(r2.rest).toBe("");
  });

  it("drops incidental prose between objects", () => {
    // Some models emit `Here is the finding: {...}` or interleaved chatter.
    // The old line-based parser silently dropped non-`{`-prefixed lines;
    // this extractor preserves that semantic by treating non-`{` chars
    // outside an object as junk.
    const buf = 'Now emitting:\n{"a":1}\n\nNext one:\n{"b":2}\n';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toEqual(['{"a":1}', '{"b":2}']);
    expect(rest).toBe("");
  });

  it("handles three concatenated objects with no separator", () => {
    const buf = '{"a":1}{"b":2}{"c":3}';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects.map((s) => JSON.parse(s))).toEqual([{ a: 1 }, { b: 2 }, { c: 3 }]);
    expect(rest).toBe("");
  });

  it("returns empty for an empty / whitespace-only buffer", () => {
    expect(extractJsonObjects("")).toEqual({ objects: [], rest: "" });
    expect(extractJsonObjects("   \n  ")).toEqual({ objects: [], rest: "" });
  });

  it("handles nested objects (e.g. call_sites arrays inside reachability)", () => {
    const buf = '{"kind":"reachability","sca_issue_id":"abc","call_sites":[{"file_path":"x.c","line":42}],"reasoning":"yes"}';
    const { objects, rest } = extractJsonObjects(buf);
    expect(objects).toHaveLength(1);
    expect(JSON.parse(objects[0])).toMatchObject({
      kind: "reachability",
      sca_issue_id: "abc",
      call_sites: [{ file_path: "x.c", line: 42 }],
    });
    expect(rest).toBe("");
  });

  it("recovers the verbatim same-line concatenation from the live FSS dry-run", () => {
    // Lifted directly from the 2026-05-22 dry-run B output — the exact byte
    // sequence that the line-based parser flagged as
    // "Unexpected non-whitespace character after JSON at position 691".
    const buf = '{"kind":"sast","cwe":"CWE-78","severity":"high","file_path":"kHardwareCommon/kHardwareCommon/kHcDef.cpp","start_line":54,"end_line":70,"summary":"kHcExecuteWithOutput concatenates arbitrary argument string","confidence":0.85}{"kind":"sast","cwe":"CWE-1104","severity":"medium","file_path":"kSnHttpServer.cpp","start_line":7,"end_line":7,"summary":"vendored jQuery 1.3.2","confidence":0.95}';
    const { objects } = extractJsonObjects(buf);
    expect(objects).toHaveLength(2);
    expect(JSON.parse(objects[0])).toMatchObject({ kind: "sast", cwe: "CWE-78" });
    expect(JSON.parse(objects[1])).toMatchObject({ kind: "sast", cwe: "CWE-1104" });
  });
});
