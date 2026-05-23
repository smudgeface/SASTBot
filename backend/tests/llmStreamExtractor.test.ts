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
import { appendBlockText, extractJsonObjects } from "../src/services/llmSastService.js";

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

describe("appendBlockText", () => {
  // The 2026-05-22 per-block diagnostic captured 7 content blocks delivered
  // by the API; 7 of 7 ended with `}` (no trailing newline). Without the
  // record-boundary newline restoration, naive concatenation produced
  // `}{` between consecutive blocks and broke JSONL parsing.

  it("inserts a newline between a closing-brace tail and an opening-brace block", () => {
    const buf = '{"kind":"sast","cwe":"CWE-22"}';
    const next = '{"kind":"sast","cwe":"CWE-345"}';
    const out = appendBlockText(buf, next);
    expect(out).toBe('{"kind":"sast","cwe":"CWE-22"}\n{"kind":"sast","cwe":"CWE-345"}');
  });

  it("does not insert a duplicate newline when the buffer already ends with one", () => {
    const buf = '{"a":1}\n';
    const next = '{"b":2}';
    expect(appendBlockText(buf, next)).toBe('{"a":1}\n{"b":2}');
  });

  it("does not insert a newline mid-record (buffer ends inside a string)", () => {
    // A record split across blocks: prev ends with a partial string,
    // next continues it. Inserting a newline here would create invalid JSON.
    const buf = '{"reasoning":"this is an unfinished';
    const next = ' string with literal content"}';
    expect(appendBlockText(buf, next)).toBe('{"reasoning":"this is an unfinished string with literal content"}');
  });

  it("does not insert a newline when the new block starts with prose, not `{`", () => {
    const buf = '{"kind":"sast","cwe":"CWE-22"}';
    const next = 'Now checking another file...';
    expect(appendBlockText(buf, next)).toBe('{"kind":"sast","cwe":"CWE-22"}Now checking another file...');
  });

  it("handles an empty buffer (first block — no boundary to restore)", () => {
    expect(appendBlockText("", '{"a":1}')).toBe('{"a":1}');
  });

  it("handles an empty new block (no-op)", () => {
    expect(appendBlockText('{"a":1}', "")).toBe('{"a":1}');
  });

  it("reconstructs well-formed JSONL when fed the exact block sequence the API delivered on 2026-05-22", () => {
    // Verbatim from /tmp/sastbot-debug/events.log on the per-block dump:
    // 7 blocks, all ending with `}`, all starting with prose or `{`.
    // Without the helper this concatenates to `}{` between records 1+2,
    // 2+3, 3+4, 4+5 — three parse errors. With the helper, the buffer
    // becomes parseable JSONL on every concatenation.
    const blocks = [
      'Found a hardcoded crypto key — emitting finding and continuing investigation.\n\n{"kind":"sast","cwe":"CWE-798","start_line":14,"end_line":14}',
      '{"kind":"sast","cwe":"CWE-327","start_line":197,"end_line":203}',
      '{"kind":"sast","cwe":"CWE-120","start_line":23,"end_line":23}',
      '{"kind":"sast","cwe":"CWE-798","start_line":13,"end_line":13}',
    ];
    let buf = "";
    for (const b of blocks) buf = appendBlockText(buf, b);
    const { objects } = extractJsonObjects(buf);
    expect(objects).toHaveLength(4);
    expect(objects.map((o) => JSON.parse(o).cwe)).toEqual(["CWE-798", "CWE-327", "CWE-120", "CWE-798"]);
  });
});
