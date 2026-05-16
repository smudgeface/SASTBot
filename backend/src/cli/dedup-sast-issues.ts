import { parseArgs } from "node:util";

import { prisma } from "../db.js";
import { mergeDuplicateSastIssues } from "../services/sastDedup.js";

/**
 * One-off broad SAST duplicate cleanup.
 *
 * Iterates every scope with > 1 pending SastIssue and runs the same
 * mergeDuplicateSastIssues logic the worker uses post-scan. Defaults to
 * dry-run (logs what would happen, writes nothing). Pass `--apply` to
 * actually merge.
 *
 *   pnpm run dedup-sast-issues          # dry-run preview
 *   pnpm run dedup-sast-issues --apply  # destructive: deletes merged rows
 *
 * Same-file only — cross-file duplicates are caught by the recheck-pass
 * `duplicate_of` verdict on the next scan.
 */
async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      apply: { type: "boolean", default: false },
      "scope-id": { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });

  const apply = values.apply === true;
  const targetScopeId = values["scope-id"];

  const scopes = await prisma.scanScope.findMany({
    where: targetScopeId ? { id: targetScopeId } : undefined,
    select: {
      id: true,
      path: true,
      displayName: true,
      repo: { select: { name: true } },
      _count: { select: { sastIssues: { where: { triageStatus: "pending" } } } },
    },
  });

  const candidates = scopes.filter((s) => s._count.sastIssues > 1);
  if (candidates.length === 0) {
    // eslint-disable-next-line no-console
    console.log("No scopes with > 1 pending SAST issue. Nothing to do.");
    return;
  }

  // eslint-disable-next-line no-console
  console.log(
    `Mode: ${apply ? "APPLY (destructive)" : "dry-run"}. Scopes to check: ${candidates.length}.\n`,
  );

  let grandTotalMerged = 0;
  let grandTotalSurvivors = 0;

  for (const scope of candidates) {
    const scopeLabel = `${scope.repo.name} ${scope.displayName ?? scope.path} (${scope.id})`;
    const result = await mergeDuplicateSastIssues(prisma, scope.id, "manual-dedup", {
      dryRun: !apply,
    });
    if (result.mergedCount === 0) {
      // eslint-disable-next-line no-console
      console.log(`  [skip] ${scopeLabel} — no merge clusters`);
      continue;
    }
    // eslint-disable-next-line no-console
    console.log(
      `  [${apply ? "merged" : "would merge"}] ${scopeLabel}: ${result.mergedCount} row(s) → ${result.survivorCount} survivor(s)`,
    );
    for (const m of result.merges) {
      // eslint-disable-next-line no-console
      console.log(
        `    · ${m.filePath}  survivor=${m.survivorId.slice(0, 8)}  merged=[${m.mergedIds.map((id) => id.slice(0, 8)).join(", ")}]  cwes=${m.cweUnion.join(",")}`,
      );
    }
    grandTotalMerged += result.mergedCount;
    grandTotalSurvivors += result.survivorCount;
  }

  // eslint-disable-next-line no-console
  console.log(
    `\nTotal: ${apply ? "merged" : "would merge"} ${grandTotalMerged} row(s) into ${grandTotalSurvivors} survivor(s).`,
  );

  if (!apply) {
    // eslint-disable-next-line no-console
    console.log("\nDry-run only. Re-run with --apply to write changes.");
  }
}

main()
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
