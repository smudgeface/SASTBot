/**
 * Same-scope SAST duplicate merger.
 *
 * Runs after persistDetection + runRecheck have settled. Collapses the
 * stream of independent per-line detections the LLM emits across scans
 * for what is conceptually one weakness (e.g. five rows pointing at
 * different lines of the same upgrade routine, with CWE labels drifting
 * across the integrity-verification family). Caller gates on
 * !hasErrorWarnings(scanRunId) so a degraded scan can't merge real
 * findings out of existence.
 */
import { Prisma, type PrismaClient } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import { bySeverity } from "./issueSort.js";

type Tx = PrismaClient | Prisma.TransactionClient;

const logger = pino({ level: loadConfig().logLevel, name: "sastDedup" });

// CWE families: each set is a cluster of CWEs the LLM frequently picks
// interchangeably for the same underlying weakness. Within a line-proximity
// cluster, two issues whose CWEs share a family (or share a raw CWE id) get
// merged. Curated, not auto-derived from the CWE graph — keep small.
const CWE_FAMILIES: ReadonlyArray<ReadonlySet<string>> = [
  // Integrity / authenticity verification.
  new Set(["CWE-345", "CWE-346", "CWE-347", "CWE-353", "CWE-494"]),
  // Injection — SQL / OS command / code / EL / generic.
  new Set(["CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-917", "CWE-74"]),
  // Path / file traversal.
  new Set(["CWE-22", "CWE-23", "CWE-36", "CWE-73"]),
  // Crypto weakness.
  new Set(["CWE-327", "CWE-328", "CWE-326", "CWE-330", "CWE-338"]),
  // Authentication / credentials.
  new Set(["CWE-287", "CWE-306", "CWE-798", "CWE-259"]),
];

const CWE_TO_FAMILY: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>();
  CWE_FAMILIES.forEach((set, idx) => {
    for (const cwe of set) m.set(cwe, idx);
  });
  return m;
})();

// Two issues' source ranges merge into the same line-proximity cluster
// when they overlap or sit within this many lines of each other.
const MAX_LINE_GAP = 5;

// The merger only touches rows in these triage states. Anything terminal
// (fixed / suppressed / false_positive) or operator-curated (confirmed /
// planned) is left alone — the operator's verdict is the source of truth
// and the worker never invisibly overwrites it.
const MERGEABLE_STATUSES: readonly string[] = ["pending"];

interface MergeableIssue {
  id: string;
  fingerprint: string;
  latestFilePath: string;
  latestStartLine: number;
  latestEndLine: number | null;
  latestSeverity: string;
  latestCweIds: string[];
  latestLlmSummary: string | null;
  latestRuleMessage: string | null;
  jiraTicketId: string | null;
}

export interface MergeDuplicatesResult {
  /** Number of issues deleted (merged into a survivor). */
  mergedCount: number;
  /** Distinct surviving issues that absorbed at least one duplicate. */
  survivorCount: number;
  /** Detail of each merge — populated for dry-run previews and observability. */
  merges: Array<{
    survivorId: string;
    mergedIds: string[];
    filePath: string;
    cweUnion: string[];
  }>;
}

export interface MergeDuplicatesOptions {
  /** When true, performs all the clustering + survivor selection but never
   *  writes to the DB. Returns the same `merges` array a real run would. */
  dryRun?: boolean;
}

export async function mergeDuplicateSastIssues(
  client: Tx,
  scopeId: string,
  scanRunId: string,
  options: MergeDuplicatesOptions = {},
): Promise<MergeDuplicatesResult> {
  const db = client as PrismaClient;

  const rows = await db.sastIssue.findMany({
    where: { scopeId, triageStatus: { in: [...MERGEABLE_STATUSES] } },
    select: {
      id: true,
      fingerprint: true,
      latestFilePath: true,
      latestStartLine: true,
      latestEndLine: true,
      latestSeverity: true,
      latestCweIds: true,
      latestLlmSummary: true,
      latestRuleMessage: true,
      jiraTicketId: true,
    },
  });

  const merges: MergeDuplicatesResult["merges"] = [];

  if (rows.length < 2) {
    return { mergedCount: 0, survivorCount: 0, merges };
  }

  const byFile = new Map<string, MergeableIssue[]>();
  for (const row of rows) {
    const list = byFile.get(row.latestFilePath) ?? [];
    list.push(row);
    byFile.set(row.latestFilePath, list);
  }

  let mergedCount = 0;
  const survivors = new Set<string>();

  for (const [filePath, fileRows] of byFile) {
    if (fileRows.length < 2) continue;

    fileRows.sort((a, b) => a.latestStartLine - b.latestStartLine || a.id.localeCompare(b.id));

    const clusters: MergeableIssue[][] = [];
    let current: MergeableIssue[] = [];
    let currentMaxEnd = -Infinity;
    for (const row of fileRows) {
      const end = row.latestEndLine ?? row.latestStartLine;
      if (current.length === 0 || row.latestStartLine <= currentMaxEnd + MAX_LINE_GAP) {
        current.push(row);
        currentMaxEnd = Math.max(currentMaxEnd, end);
      } else {
        clusters.push(current);
        current = [row];
        currentMaxEnd = end;
      }
    }
    if (current.length > 0) clusters.push(current);

    for (const cluster of clusters) {
      if (cluster.length < 2) continue;

      // Union-find within the cluster on family or raw-CWE overlap.
      const parent = new Map<string, string>(cluster.map((r) => [r.id, r.id]));
      const find = (x: string): string => {
        let root = x;
        while (parent.get(root) !== root) root = parent.get(root)!;
        let cur = x;
        while (parent.get(cur) !== root) {
          const next = parent.get(cur)!;
          parent.set(cur, root);
          cur = next;
        }
        return root;
      };
      const union = (a: string, b: string): void => {
        const ra = find(a);
        const rb = find(b);
        if (ra !== rb) parent.set(ra, rb);
      };

      const mergeKey = (r: MergeableIssue): Set<string> => {
        const keys = new Set<string>();
        for (const cwe of r.latestCweIds) {
          const fam = CWE_TO_FAMILY.get(cwe);
          keys.add(fam !== undefined ? `fam:${fam}` : `cwe:${cwe}`);
        }
        // Rows with no CWE labels stay isolated.
        if (keys.size === 0) keys.add(`row:${r.id}`);
        return keys;
      };

      const keysByRow = new Map<string, Set<string>>();
      for (const r of cluster) keysByRow.set(r.id, mergeKey(r));

      for (let i = 0; i < cluster.length; i++) {
        for (let j = i + 1; j < cluster.length; j++) {
          const ki = keysByRow.get(cluster[i].id)!;
          const kj = keysByRow.get(cluster[j].id)!;
          for (const k of ki) {
            if (kj.has(k)) {
              union(cluster[i].id, cluster[j].id);
              break;
            }
          }
        }
      }

      const groups = new Map<string, MergeableIssue[]>();
      for (const r of cluster) {
        const root = find(r.id);
        const list = groups.get(root) ?? [];
        list.push(r);
        groups.set(root, list);
      }

      for (const members of groups.values()) {
        if (members.length < 2) continue;

        // Survivor: highest severity → widest range → lowest id.
        const sorted = [...members].sort((a, b) => {
          const sev = bySeverity(a.latestSeverity, b.latestSeverity);
          if (sev !== 0) return sev;
          const widthA = (a.latestEndLine ?? a.latestStartLine) - a.latestStartLine;
          const widthB = (b.latestEndLine ?? b.latestStartLine) - b.latestStartLine;
          if (widthA !== widthB) return widthB - widthA;
          return a.id.localeCompare(b.id);
        });
        const survivor = sorted[0];
        const toMerge = sorted.slice(1);

        const cweUnion = new Set<string>(survivor.latestCweIds);
        for (const m of toMerge) for (const c of m.latestCweIds) cweUnion.add(c);

        const seeAlsoParts = toMerge.map((m) => {
          const cwePart = m.latestCweIds.join(",") || "CWE-?";
          const range = m.latestEndLine != null && m.latestEndLine !== m.latestStartLine
            ? `L${m.latestStartLine}-${m.latestEndLine}`
            : `L${m.latestStartLine}`;
          return `${cwePart} ${range}`;
        });
        const baseSummary = (survivor.latestLlmSummary ?? survivor.latestRuleMessage ?? "").trim();
        const newSummary = `${baseSummary}\n\nSee also: ${seeAlsoParts.join("; ")}`.trim();

        // Lift a jira ticket from a merged row only if the survivor doesn't
        // already have one. Avoids silently swapping an operator-linked ticket.
        const liftedJiraTicketId: string | null =
          survivor.jiraTicketId ??
          toMerge.find((m) => m.jiraTicketId != null)?.jiraTicketId ??
          null;

        const mergedFingerprints = toMerge.map((m) => m.fingerprint);

        if (!options.dryRun) {
          // Re-point cross-table refs first so we never leave a ScaIssue
          // pointing at a fingerprint whose row we just deleted.
          await db.scaIssue.updateMany({
            where: { scopeId, reachableViaSastFingerprint: { in: mergedFingerprints } },
            data: { reachableViaSastFingerprint: survivor.fingerprint },
          });

          await db.sastIssue.update({
            where: { id: survivor.id },
            data: {
              latestCweIds: Array.from(cweUnion),
              latestLlmSummary: newSummary,
              ...(liftedJiraTicketId !== survivor.jiraTicketId
                ? { jiraTicketId: liftedJiraTicketId }
                : {}),
            },
          });

          await db.sastIssue.deleteMany({
            where: { id: { in: toMerge.map((m) => m.id) } },
          });
        }

        mergedCount += toMerge.length;
        survivors.add(survivor.id);
        merges.push({
          survivorId: survivor.id,
          mergedIds: toMerge.map((m) => m.id),
          filePath,
          cweUnion: Array.from(cweUnion),
        });

        logger.info(
          {
            scopeId,
            scanRunId,
            survivorId: survivor.id,
            mergedIds: toMerge.map((m) => m.id),
            filePath,
            cweUnion: Array.from(cweUnion),
            dryRun: options.dryRun === true,
          },
          options.dryRun
            ? "[sastDedup] would merge duplicates (dry-run)"
            : "[sastDedup] merged duplicates",
        );
      }
    }
  }

  return { mergedCount, survivorCount: survivors.size, merges };
}
