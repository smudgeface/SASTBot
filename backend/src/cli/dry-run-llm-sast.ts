/**
 * CLI: `pnpm run dry-run-llm-sast --scope-id <id>`
 *
 * Phase 6b dev tool. Picks up a real ScanScope from the DB, locates its cached
 * clone (or accepts an explicit --clone-dir override), pulls the high+critical
 * SCA hints from the latest successful scan, and invokes
 * llmSastService.runDetection. Prints parsed records as JSON-Lines on stdout
 * and parse errors on stderr. No DB writes, no scan-run row.
 *
 * Intended to run inside the worker container where /app/clones is mounted
 * and `claude` is on PATH.
 */
import { parseArgs } from "node:util";
import path from "node:path";

import { prisma } from "../db.js";
import {
  applyRecheckVerdicts,
  cleanupTmp,
  persistDetection,
  type RecheckIssueInput,
  runDetection,
  runRecheck,
  type ScaHintInput,
} from "../services/llmSastService.js";

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "scope-id": { type: "string" },
      "clone-dir": { type: "string" },
      "token-budget": { type: "string" },
      "max-sca-hints": { type: "string" },
      // When set, the orchestrator persists results into a real ScanRun row
      // instead of just logging them. The new run is created up-front so we
      // can attach SbomComponent / SastIssue rows to it.
      persist: { type: "boolean", default: false },
      // Skip detection; load every active SastIssue for the scope and run
      // the recheck pass against it. Useful for verifying recheck verdicts
      // without driving a full scan first.
      "recheck-only": { type: "boolean", default: false },
      // For --recheck-only, an upper bound on issues sent into the pass.
      "max-recheck-issues": { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });

  const scopeId = values["scope-id"];
  if (!scopeId) {
    // eslint-disable-next-line no-console
    console.error(
      "Usage: dry-run-llm-sast --scope-id <id> [--clone-dir /path] [--token-budget 300000] [--max-sca-hints 50]",
    );
    process.exit(2);
  }

  const tokenBudget = Number(values["token-budget"] ?? "300000");
  const maxScaHints = Number(values["max-sca-hints"] ?? "50");

  const scope = await prisma.scanScope.findUnique({
    where: { id: scopeId },
    include: { repo: true },
  });
  if (!scope) {
    // eslint-disable-next-line no-console
    console.error(`Scope ${scopeId} not found`);
    process.exit(1);
  }

  // Locate the clone. SASTBot caches at /app/clones/<repoId>; the scope_path
  // sits under that. test-vuln-repo has scope_path "/" so the scope dir IS
  // the clone root.
  const cloneRoot = process.env.CLONE_CACHE_DIR ?? "/app/clones";
  const repoCloneDir = path.join(cloneRoot, scope.repoId);
  const scopePath = scope.path === "/" ? "" : scope.path.replace(/^\//, "");
  const scopeDir = path.join(repoCloneDir, scopePath);

  const cloneDir = values["clone-dir"] ?? scopeDir;

  // Pull high+critical SCA hints from the latest issues in this scope.
  const scaIssues = await prisma.scaIssue.findMany({
    where: {
      scopeId: scope.id,
      latestFindingType: "cve",
      latestSeverity: { in: ["critical", "high"] },
    },
    orderBy: [
      { latestSeverity: "asc" },
      { latestCvssScore: "desc" },
      { lastSeenAt: "desc" },
    ],
    take: maxScaHints,
  });

  const scaHints: ScaHintInput[] = scaIssues.map((i) => ({
    id: i.id,
    package: i.packageName,
    version: i.latestPackageVersion,
    cve_id: i.latestCveId,
    osv_id: i.osvId,
    cvss_score: i.latestCvssScore,
    summary: i.latestSummary,
  }));

  // ── --recheck-only branch ──────────────────────────────────────────────
  if (values["recheck-only"]) {
    const recheckBudget = Number(values["token-budget"] ?? "50000");
    const maxRecheckIssues = Number(values["max-recheck-issues"] ?? "200");

    // Pull active SastIssues for the scope (the same set the worker would
    // route through recheck after a real scan).
    const active = await prisma.sastIssue.findMany({
      where: {
        scopeId: scope.id,
        triageStatus: { in: ["pending", "confirmed", "planned", "error"] },
      },
      orderBy: { lastSeenAt: "desc" },
      take: maxRecheckIssues,
    });

    const issues: RecheckIssueInput[] = active.map((i) => ({
      id: i.id,
      file: i.latestFilePath,
      line: i.latestStartLine,
      summary: i.latestRuleMessage ?? i.latestRuleId,
      snippet: i.latestSnippet ?? "",
      cwe: (i.latestCweIds[0] ?? "CWE-UNKNOWN"),
    }));

    const fakeScanRunId = `recheck-${Date.now().toString(36)}`;
    // eslint-disable-next-line no-console
    console.error(
      `[dry-run] recheck-only: scope=${scope.id} cloneDir=${cloneDir} issues=${issues.length} budget=${recheckBudget}`,
    );

    try {
      const result = await runRecheck({
        scanRunId: fakeScanRunId,
        scopeDir: cloneDir,
        scopePath: scope.path,
        issues,
        tokenBudget: recheckBudget,
        orgId: scope.repo.orgId ?? null,
      });

      for (const v of result.verdicts) {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(v));
      }
      if (result.parseErrors.length > 0) {
        // eslint-disable-next-line no-console
        console.error(`\n[dry-run] ${result.parseErrors.length} parse error(s):`);
        for (const e of result.parseErrors) {
          // eslint-disable-next-line no-console
          console.error(`  - ${e.reason} :: ${e.raw.slice(0, 200)}`);
        }
      }

      if (values.persist) {
        // Persist verdicts against a fresh ScanRun so lastSeenScanRunId advances.
        const run = await prisma.scanRun.create({
          data: {
            repoId: scope.repoId,
            scopeId: scope.id,
            orgId: scope.repo.orgId ?? null,
            status: "success",
            triggeredBy: "user",
            startedAt: new Date(),
            finishedAt: new Date(),
            llmInputTokens: result.usage.inputTokens,
            llmOutputTokens: result.usage.outputTokens,
            llmRequestCount: result.usage.requestCount,
          },
        });
        const applyResult = await applyRecheckVerdicts(prisma, {
          scanRunId: run.id,
          scopeId: scope.id,
          inputIssues: issues,
          verdicts: result.verdicts,
        });
        // eslint-disable-next-line no-console
        console.error(`[dry-run] applied: ${JSON.stringify(applyResult)}`);
      }

      // eslint-disable-next-line no-console
      console.error(
        `\n[dry-run] exitCode=${result.exitCode} durationMs=${result.durationMs} verdicts=${result.verdicts.length} parseErrors=${result.parseErrors.length}`,
      );
      // eslint-disable-next-line no-console
      console.error(
        `[dry-run] usage: input=${result.usage.inputTokens} output=${result.usage.outputTokens} cache_read=${result.usage.cacheReadInputTokens} requests=${result.usage.requestCount} cost_usd=${result.usage.estimatedUsdCost}`,
      );
    } finally {
      await cleanupTmp(fakeScanRunId);
      await prisma.$disconnect();
    }
    return;
  }
  // ───────────────────────────────────────────────────────────────────────

  // If --persist, create a real ScanRun row up front so SbomComponent /
  // SastIssue rows have an FK target. Otherwise use a synthetic id and
  // skip persistence.
  let scanRunId: string;
  let persistedRunCreated = false;
  if (values.persist) {
    const run = await prisma.scanRun.create({
      data: {
        repoId: scope.repoId,
        scopeId: scope.id,
        orgId: scope.repo.orgId ?? null,
        status: "running",
        triggeredBy: "user",
        startedAt: new Date(),
      },
    });
    scanRunId = run.id;
    persistedRunCreated = true;
  } else {
    scanRunId = `dryrun-${Date.now().toString(36)}`;
  }

  // eslint-disable-next-line no-console
  console.error(
    `[dry-run] scope=${scope.id} repo=${scope.repo.name}@${scope.repo.defaultBranch} cloneDir=${cloneDir} scaHints=${scaHints.length} budget=${tokenBudget} persist=${values.persist} scanRunId=${scanRunId}`,
  );

  try {
    const result = await runDetection({
      scanRunId,
      scopeId: scope.id,
      scopeDir: cloneDir,
      repoName: scope.repo.name,
      repoBranch: scope.repo.defaultBranch,
      ignorePaths: scope.repo.ignorePaths as string[],
      scaHints,
      tokenBudget,
      orgId: scope.repo.orgId ?? null,
    });

    // Emit parsed records on stdout, one JSON object per line.
    for (const r of result.records) {
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(r));
    }

    // Errors on stderr.
    if (result.parseErrors.length > 0) {
      // eslint-disable-next-line no-console
      console.error(`\n[dry-run] ${result.parseErrors.length} parse error(s):`);
      for (const e of result.parseErrors) {
        // eslint-disable-next-line no-console
        console.error(`  - ${e.reason} :: ${e.raw.slice(0, 200)}`);
      }
    }

    if (values.persist) {
      const persistResult = await persistDetection(prisma, {
        scanRunId,
        scopeId: scope.id,
        scopeDir: cloneDir,
        scopePath: scope.path,
        orgId: scope.repo.orgId ?? null,
        records: result.records,
        modelName: "claude-code-cli",
      });
      // eslint-disable-next-line no-console
      console.error(`[dry-run] persisted: ${JSON.stringify(persistResult)}`);

      // Mark the run successful + carry usage onto the row so it surfaces
      // in the existing scan-detail "LLM usage" card.
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: {
          status: "success",
          finishedAt: new Date(),
          llmInputTokens: result.usage.inputTokens,
          llmOutputTokens: result.usage.outputTokens,
          llmRequestCount: result.usage.requestCount,
        },
      });
    }

    // eslint-disable-next-line no-console
    console.error(
      `\n[dry-run] exitCode=${result.exitCode} durationMs=${result.durationMs} records=${result.records.length} parseErrors=${result.parseErrors.length}`,
    );
    // eslint-disable-next-line no-console
    console.error(
      `[dry-run] usage: input=${result.usage.inputTokens} output=${result.usage.outputTokens} cache_read=${result.usage.cacheReadInputTokens} cache_create=${result.usage.cacheCreationInputTokens} requests=${result.usage.requestCount} cost_usd=${result.usage.estimatedUsdCost}`,
    );
  } catch (err) {
    if (persistedRunCreated) {
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: {
          status: "failed",
          finishedAt: new Date(),
          error: err instanceof Error ? err.message : String(err),
        },
      }).catch(() => undefined);
    }
    throw err;
  } finally {
    await cleanupTmp(scanRunId);
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("[dry-run] failed:", err);
  process.exit(1);
});
