/**
 * M13 Phase B probe — observe what `claude -p --output-format json` delivers.
 *
 * Goal: before refactoring `spawnClaudeAndStream` to support a
 * "structured-output" response shape, verify empirically what comes
 * through stdout in structured-output mode. Specifically:
 *
 *   1. Does anything arrive BEFORE the final JSON blob (tool-use
 *      events, partial assistant messages, usage updates)?
 *   2. Does the final JSON include `structured_output`, `usage`,
 *      subtype info, retry count, cost?
 *   3. How does this compare to `stream-json`'s per-event flow?
 *
 * One-off diagnostic; run by hand inside the backend container.
 * Uses --effort low + a minimal prompt + a tiny schema to keep cost
 * well under $0.10. NOT a permanent feature.
 *
 *   docker compose exec backend pnpm exec tsx \
 *     src/cli/probe-claude-structured-output.ts
 *
 * Output: one line per stdout chunk with `[+Nms BYTES]` prefix, then
 * a summary block at the end with parsed event counts and the final
 * structured_output shape.
 */
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

import { prisma } from "../db.js";
import { decodeCredential } from "../services/credentialService.js";
import { getOrCreateSettings } from "../services/settingsService.js";

const CLAUDE_UID = 1001;
const CLAUDE_GID = 1001;

// Minimal schema: model must emit { ok: boolean, note: string }.
// Tiny enough that retries cost ~nothing and the result is unambiguous.
const TINY_SCHEMA = {
  type: "object",
  properties: {
    ok: { type: "boolean" },
    note: { type: "string" },
  },
  required: ["ok", "note"],
  additionalProperties: false,
};

// Force at least one tool call so we can see whether tool-use events
// surface before the final JSON. "Read README.md and tell me if it
// exists" should produce one Read tool call.
const USER_PROMPT = [
  "Use the Read tool to attempt to read the file at path /tmp/probe-target.txt.",
  "Then emit { ok: <true if you successfully read it, false otherwise>, ",
  "note: \"<one short sentence describing what you observed>\" }",
  "as the final structured output.",
].join("\n");

async function main(): Promise<void> {
  // Pick the first org that has LLM config — production deployments
  // configure the LLM on the org-scoped row, not the null-org default.
  const orgConfig = await prisma.appSettings.findFirst({
    where: { llmBaseUrl: { not: null }, llmModel: { not: null }, llmCredentialId: { not: null } },
  });
  if (!orgConfig) {
    throw new Error("LLM not configured on any org (need llmBaseUrl + llmModel + llmCredentialId in AppSettings)");
  }
  const settings = await getOrCreateSettings(orgConfig.orgId);
  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    throw new Error("LLM not configured (need llmBaseUrl + llmModel + llmCredentialId in AppSettings)");
  }
  const cred = await decodeCredential(settings.llmCredentialId);
  if (cred.kind !== "llm_api_key") throw new Error(`Expected llm_api_key credential, got ${cred.kind}`);

  const probeDir = "/tmp/sastbot-probe";
  const claudeHome = path.join(probeDir, "home");
  await fs.rm(probeDir, { recursive: true, force: true });
  await fs.mkdir(claudeHome, { recursive: true, mode: 0o755 });
  await fs.chown(claudeHome, CLAUDE_UID, CLAUDE_GID).catch(() => { /* fs may not support chown */ });

  // The "force a tool call" target — give the LLM something to read.
  const targetPath = "/tmp/probe-target.txt";
  await fs.writeFile(targetPath, "probe target — if you can read this, return ok=true\n", { mode: 0o644 });

  // CLI 2.1.144 expects --json-schema as inline JSON, not a file path.
  // M13_PLAN preferred file paths for auditability + argv-size concerns;
  // empirical test says we can't have that. Inline it is.
  const schemaInline = JSON.stringify(TINY_SCHEMA);

  const mode = process.argv[2] ?? "json";
  if (!["json", "stream-json"].includes(mode)) {
    throw new Error(`Unknown mode '${mode}'. Pass 'json' or 'stream-json'.`);
  }

  const args = [
    "-p",
    USER_PROMPT,
    "--model",
    settings.llmModel,
    "--effort",
    "low",
    "--allowed-tools",
    "Bash Read Glob Grep",
    "--permission-mode",
    "bypassPermissions",
    "--output-format",
    mode,
    "--json-schema",
    schemaInline,
    ...(mode === "stream-json" ? ["--verbose"] : []),
  ];

  // eslint-disable-next-line no-console
  console.log("[probe] args:", args.join(" "));
  // eslint-disable-next-line no-console
  console.log("[probe] schema inline length:", schemaInline.length, "bytes");

  const startedAt = Date.now();
  const stdoutChunks: Array<{ atMs: number; size: number; text: string }> = [];
  const stderrChunks: Array<{ atMs: number; size: number; text: string }> = [];

  await new Promise<void>((resolve) => {
    const proc = spawn("claude", args, {
      cwd: probeDir,
      env: {
        ...process.env,
        ANTHROPIC_API_KEY: cred.value,
        ANTHROPIC_BASE_URL: settings.llmBaseUrl ?? undefined,
        HOME: claudeHome,
        USER: "claudeuser",
      },
      stdio: ["ignore", "pipe", "pipe"],
      uid: CLAUDE_UID,
      gid: CLAUDE_GID,
    });

    proc.stdout.on("data", (buf: Buffer) => {
      const atMs = Date.now() - startedAt;
      const text = buf.toString("utf8");
      stdoutChunks.push({ atMs, size: buf.length, text });
      // eslint-disable-next-line no-console
      console.log(`[stdout +${atMs}ms ${buf.length}B] ${text.slice(0, 200)}${text.length > 200 ? "…" : ""}`);
    });
    proc.stderr.on("data", (buf: Buffer) => {
      const atMs = Date.now() - startedAt;
      const text = buf.toString("utf8");
      stderrChunks.push({ atMs, size: buf.length, text });
      // eslint-disable-next-line no-console
      console.log(`[stderr +${atMs}ms ${buf.length}B] ${text.slice(0, 200)}${text.length > 200 ? "…" : ""}`);
    });
    proc.on("close", (code) => {
      // eslint-disable-next-line no-console
      console.log(`[probe] process closed, exit=${code}, total elapsed=${Date.now() - startedAt}ms`);
      resolve();
    });
  });

  // eslint-disable-next-line no-console
  console.log("\n========== SUMMARY ==========");
  // eslint-disable-next-line no-console
  console.log(`stdout chunks: ${stdoutChunks.length}, total bytes: ${stdoutChunks.reduce((s, c) => s + c.size, 0)}`);
  // eslint-disable-next-line no-console
  console.log(`stderr chunks: ${stderrChunks.length}, total bytes: ${stderrChunks.reduce((s, c) => s + c.size, 0)}`);

  const fullStdout = stdoutChunks.map((c) => c.text).join("");
  // eslint-disable-next-line no-console
  console.log(`\n--- full stdout (${fullStdout.length} bytes) ---`);
  // eslint-disable-next-line no-console
  console.log(fullStdout);

  // Try to parse as JSON object.
  try {
    const parsed = JSON.parse(fullStdout);
    // eslint-disable-next-line no-console
    console.log("\n--- parsed top-level shape ---");
    // eslint-disable-next-line no-console
    console.log("keys:", Object.keys(parsed));
    if (typeof parsed === "object" && parsed !== null) {
      for (const k of Object.keys(parsed)) {
        const v = (parsed as Record<string, unknown>)[k];
        const summary = typeof v === "object" && v !== null
          ? `[${Array.isArray(v) ? "array len=" + (v as unknown[]).length : "object keys=" + Object.keys(v as Record<string, unknown>).join(",")}]`
          : JSON.stringify(v);
        // eslint-disable-next-line no-console
        console.log(`  ${k}: ${summary}`);
      }
    }
  } catch (err) {
    // Maybe NDJSON?
    const lines = fullStdout.split("\n").filter((l) => l.trim().length > 0);
    // eslint-disable-next-line no-console
    console.log(`\n[probe] stdout is NOT one JSON value; split into ${lines.length} non-empty lines`);
    lines.slice(0, 5).forEach((line, i) => {
      // eslint-disable-next-line no-console
      console.log(`  line[${i}]: ${line.slice(0, 200)}${line.length > 200 ? "…" : ""}`);
    });
  }

  // eslint-disable-next-line no-console
  console.log("\n========== TIMING ==========");
  // eslint-disable-next-line no-console
  console.log("Per-chunk arrival times (ms after spawn):");
  for (const c of stdoutChunks) {
    // eslint-disable-next-line no-console
    console.log(`  +${c.atMs}ms  ${c.size}B`);
  }

  await prisma.$disconnect();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("[probe] error:", err);
  process.exit(1);
});
