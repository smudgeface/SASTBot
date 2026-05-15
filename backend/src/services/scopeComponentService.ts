/**
 * scopeComponentService.ts — scope-level component state.
 *
 * The two exports of note:
 *   - `persistScanComponentsToScopeState`: the in-flight scan writer. Called
 *     after Stage 2 (LLM augmentation) by the worker. Uses the deterministic
 *     componentMatch chain to match each emitted sbom_component against
 *     existing scope_components, updating identity fields on match and
 *     inserting on miss.
 *   - `materializeRecoveredComponents` / `rebuildComponentsFromScopeState`:
 *     consumed by the SBOM recheck phase to keep the worker's in-memory list
 *     in sync with the scope-level truth.
 *
 * The bootstrap backfill that previously ran on every worker boot
 * (backfillScopeComponentsFromLatestScans) was removed: it predated the
 * componentMatch chain, used a NULL-distinct ON CONFLICT clause that quietly
 * duplicated version-NULL rows on each restart, and is no longer needed —
 * the scan flow now bootstraps scope_components natively.
 */

import { pino } from "pino";
import { prisma } from "../db.js";
import { loadConfig } from "../config.js";
import type { SbomComponent } from "@prisma/client";
import {
  matchComponent,
  type ComponentIdentity,
  type MatchResult,
} from "./componentMatch.js";

const logger = pino({ level: loadConfig().logLevel, name: "scopeComponentService" });

// ---------------------------------------------------------------------------
// Live scan path: persist augmented sbom_components into scope_components
// ---------------------------------------------------------------------------

/**
 * For every component surfaced by this scan run's augmentation pass, upsert
 * into `scope_components` (keyed by scope_id, name, version, purl) and insert
 * the `scan_run_components` join row.
 *
 * Rules per the plan (docs/SBOM_COMPONENT_RECHECK_PLAN.md):
 * - Insert: set firstSeenScanRunId = lastSeenScanRunId = scanRunId,
 *   lastSeenAt = now, dismissedStatus = 'active', source = 'scan'.
 * - Existing 'active' or 'removed' row hit: update lastSeenScanRunId,
 *   lastSeenAt. Flip 'removed' back to 'active' (the component is back).
 * - Existing 'manual_override' row: leave dismissedStatus / reason as-is.
 *   Update lastSeenScanRunId and lastSeenAt only.
 *
 * The join row (scan_run_components) always uses the component's discoveryMethod
 * value so the per-scan audit trail reflects how it was found.
 */
export async function persistScanComponentsToScopeState(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  components: SbomComponent[],
): Promise<{ upserted: number; joinsInserted: number }> {
  let upserted = 0;
  let joinsInserted = 0;
  const tierCounts: Record<string, number> = {};

  // Pre-fetch all active scope_components once. The componentMatch chain
  // operates on this cache; new inserts are appended to the cache so a
  // later incoming component with the same identity matches the just-
  // inserted row instead of producing a sibling duplicate.
  type CacheRow = ComponentIdentity & { id: string };
  const initialRows = await prisma.$queryRawUnsafe<
    Array<{
      id: string;
      name: string;
      version: string | null;
      purl: string;
      ecosystem: string | null;
      component_root: string | null;
      evidence_path: string | null;
      cpe: string | null;
      manifest_file: string | null;
    }>
  >(
    `SELECT id, name, version, purl, ecosystem,
            component_root, evidence_path, cpe, manifest_file
     FROM scope_components
     WHERE scope_id = $1::uuid
       AND dismissed_status = 'active'`,
    scopeId,
  );
  const cache: CacheRow[] = initialRows.map((r) => ({
    id: r.id,
    name: r.name,
    version: r.version,
    purl: r.purl,
    ecosystem: r.ecosystem,
    componentRoot: r.component_root,
    evidencePath: r.evidence_path,
    cpe: r.cpe,
    manifestFile: r.manifest_file,
  }));

  for (const c of components) {
    // Extract evidence_path from llmEvidence if not already a top-level field
    // (back-compat with rows that pre-date the new fields).
    let evidencePath: string | null = (c as unknown as { evidencePath?: string | null }).evidencePath ?? null;
    if (!evidencePath && c.llmEvidence && typeof c.llmEvidence === "object") {
      const ev = c.llmEvidence as Record<string, unknown>;
      if (typeof ev.path === "string" && ev.path) {
        evidencePath = ev.path;
      }
    }

    const componentRoot = (c as unknown as { componentRoot?: string | null }).componentRoot ?? null;
    // Evidence is jsonb on the row — pull it as unknown and coerce to a JSON
    // string for the SQL ::jsonb cast below. Falls back to an empty array.
    const rawEvidence = (c as unknown as { evidence?: unknown }).evidence;
    const evidenceJson = Array.isArray(rawEvidence) ? JSON.stringify(rawEvidence) : "[]";
    const incomingCpe = (c as unknown as { cpe?: string | null }).cpe ?? null;
    const incoming: ComponentIdentity = {
      name: c.name,
      version: c.version ?? null,
      purl: c.purl,
      ecosystem: c.ecosystem ?? null,
      componentRoot,
      evidencePath,
      cpe: incomingCpe,
      manifestFile: c.manifestFile ?? null,
    };

    try {
      let scopeComponentId: string | null = null;
      let matchTier: MatchResult["tier"] | "insert" = "insert";

      const match = matchComponent(incoming, cache);
      if (match) {
        scopeComponentId = match.matchedId;
        matchTier = match.tier;
        // Update the matched row: bump lifecycle + populate componentRoot /
        // evidence if they were empty on the existing row (so the identity
        // strengthens over time as the LLM emits richer data). jsonb_array_length
        // is the jsonb equivalent of array_length here.
        await prisma.$executeRawUnsafe(
          `UPDATE scope_components SET
            last_seen_scan_run_id = $1::uuid,
            last_seen_at          = now(),
            updated_at            = now(),
            component_root = COALESCE(component_root, $3),
            evidence = CASE
              WHEN evidence IS NULL OR jsonb_array_length(evidence) = 0
                THEN $4::jsonb
              ELSE evidence
            END,
            dismissed_status = CASE
              WHEN dismissed_status = 'removed' THEN 'active'
              ELSE dismissed_status
            END,
            dismissed_reason = CASE
              WHEN dismissed_status = 'removed' THEN NULL
              ELSE dismissed_reason
            END,
            dismissed_at = CASE
              WHEN dismissed_status = 'removed' THEN NULL
              ELSE dismissed_at
            END
          WHERE id = $2::uuid`,
          scanRunId,
          scopeComponentId,
          componentRoot ?? null,
          evidenceJson,
        );
        upserted++;
        // Strengthen the cached identity so subsequent incoming components
        // match against the now-richer row.
        const cached = cache.find((r) => r.id === scopeComponentId);
        if (cached && !cached.componentRoot && componentRoot) {
          cached.componentRoot = componentRoot;
        }
      } else {
        // No match — INSERT a fresh row. The (scope_id, name, version, purl)
        // ON CONFLICT clause guards against the rare race where componentMatch
        // missed an existing row but the strict identity collides (e.g. an
        // identical row inserted in the same loop with NULL version against
        // PG's NULL-distinct semantics).
        await prisma.$executeRawUnsafe(
          `INSERT INTO scope_components (
            id, scope_id, org_id,
            name, version, purl, ecosystem,
            licenses, component_type, scope, is_dev_only,
            manifest_file, discovery_method, evidence_line,
            evidence_path, component_root, evidence,
            llm_evidence, cpe,
            source, dismissed_status,
            first_seen_scan_run_id, last_seen_scan_run_id, last_seen_at,
            created_at, updated_at
          )
          VALUES (
            gen_random_uuid(), $1::uuid, $2::uuid,
            $3, $4, $5, $6,
            $7::text[], $8, $9, $10,
            $11, $12, $13,
            $14, $15, $16::jsonb,
            $17::jsonb, $18,
            'scan', 'active',
            $19::uuid, $19::uuid, now(),
            now(), now()
          )
          ON CONFLICT (scope_id, name, version, purl) DO UPDATE
            SET last_seen_scan_run_id = EXCLUDED.last_seen_scan_run_id,
                last_seen_at          = EXCLUDED.last_seen_at,
                updated_at            = now(),
                component_root        = COALESCE(scope_components.component_root, EXCLUDED.component_root),
                evidence = CASE
                  WHEN scope_components.evidence IS NULL OR jsonb_array_length(scope_components.evidence) = 0
                    THEN EXCLUDED.evidence
                  ELSE scope_components.evidence
                END,
                dismissed_status = CASE
                  WHEN scope_components.dismissed_status = 'removed' THEN 'active'
                  ELSE scope_components.dismissed_status
                END,
                dismissed_reason = CASE
                  WHEN scope_components.dismissed_status = 'removed' THEN NULL
                  ELSE scope_components.dismissed_reason
                END,
                dismissed_at = CASE
                  WHEN scope_components.dismissed_status = 'removed' THEN NULL
                  ELSE scope_components.dismissed_at
                END`,
          scopeId,
          orgId ?? null,
          c.name,
          c.version ?? null,
          c.purl,
          c.ecosystem ?? null,
          `{${c.licenses.map((l) => `"${l.replace(/"/g, '\\"')}"`).join(",")}}`,
          c.componentType,
          c.scope ?? null,
          c.isDevOnly,
          c.manifestFile ?? null,
          c.discoveryMethod ?? "manifest",
          c.evidenceLine ?? null,
          evidencePath ?? null,
          componentRoot ?? null,
          evidenceJson,
          c.llmEvidence !== null ? JSON.stringify(c.llmEvidence) : null,
          incomingCpe,
          scanRunId,
        );

        upserted++;

        const inserted = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
          `SELECT id FROM scope_components
           WHERE scope_id = $1::uuid
             AND name = $2
             AND purl = $3
             AND (version = $4 OR ($4 IS NULL AND version IS NULL))
           LIMIT 1`,
          scopeId,
          c.name,
          c.purl,
          c.version ?? null,
        );

        if (inserted.length === 0) {
          logger.warn(
            { scopeId, purl: c.purl },
            "[scopeComponentService] persistScanComponents: could not find scope_component after upsert — skipping join row",
          );
          continue;
        }

        scopeComponentId = inserted[0]!.id;

        // Append to the cache so subsequent components in this loop can
        // match against this row instead of inserting a sibling duplicate.
        cache.push({ ...incoming, id: scopeComponentId });
      }

      tierCounts[matchTier] = (tierCounts[matchTier] ?? 0) + 1;

      const joinInserted = await prisma.$executeRawUnsafe(
        `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
         VALUES ($1::uuid, $2::uuid, $3)
         ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING`,
        scanRunId,
        scopeComponentId,
        c.discoveryMethod ?? "manifest",
      );

      joinsInserted += joinInserted;
    } catch (err) {
      logger.warn(
        { err: (err as Error).message, scopeId, purl: c.purl },
        "[scopeComponentService] persistScanComponents: error upserting component — skipping",
      );
    }
  }

  logger.info(
    { scanRunId, scopeId, upserted, joinsInserted, tierCounts },
    "[scopeComponentService] persistScanComponentsToScopeState complete",
  );

  return { upserted, joinsInserted };
}

// ---------------------------------------------------------------------------
// Rebuild the in-memory components array from scope_components post-recheck.
// ---------------------------------------------------------------------------

/**
 * After all recheck verdicts (present/removed/merge) have been applied,
 * rebuild the in-memory components array from `scope_components` active rows
 * that have a `scan_run_components` join for this scan_run.
 *
 * This ensures OSV/NVD/detection see the canonical scope-state names, not
 * whatever labels the LLM emitted this run that may now be merged away.
 *
 * For each returned row, also ensures a corresponding `sbom_components` row
 * exists for this scan_run (insert if missing). This keeps the curated SBOM
 * endpoint consistent with the in-memory list.
 */
export async function rebuildComponentsFromScopeState(
  scanRunId: string,
  scopeId: string,
): Promise<SbomComponent[]> {
  // Fetch all scope_components that have a join row for this scan_run and
  // are still active (merges delete scope_components rows, so removed/dropped
  // ones will naturally be absent here).
  const scopeRows = await prisma.$queryRawUnsafe<Array<{
    id: string;
    name: string;
    version: string | null;
    purl: string;
    ecosystem: string | null;
    licenses: string[];
    component_type: string;
    scope: string | null;
    is_dev_only: boolean;
    manifest_file: string | null;
    discovery_method: string | null;
    evidence_line: number | null;
    evidence_path: string | null;
    llm_evidence: unknown;
    cpe: string | null;
  }>>(
    `SELECT
       sc.id, sc.name, sc.version, sc.purl, sc.ecosystem,
       sc.licenses, sc.component_type, sc.scope, sc.is_dev_only,
       sc.manifest_file, sc.discovery_method, sc.evidence_line,
       sc.evidence_path, sc.llm_evidence, sc.cpe
     FROM scope_components sc
     INNER JOIN scan_run_components src ON src.scope_component_id = sc.id
       AND src.scan_run_id = $1::uuid
     WHERE sc.scope_id = $2::uuid
       AND sc.dismissed_status = 'active'
     ORDER BY sc.name ASC`,
    scanRunId,
    scopeId,
  );

  if (scopeRows.length === 0) {
    logger.info({ scanRunId, scopeId }, "[scopeComponentService] rebuildComponentsFromScopeState: no rows");
    return [];
  }

  const rebuilt: SbomComponent[] = [];

  for (const sc of scopeRows) {
    // Ensure a sbom_components row exists for this scan_run / component.
    // Conflict target is (scan_run_id, purl): the unique index added in
    // 20260515090000_dedup_sbom_components_by_purl. Without an explicit
    // target this clause was a no-op (sbom_components has no other unique
    // constraint), so every merge-followed-by-rebuild used to duplicate
    // rows for every active scope_component. See migration comment.
    await prisma.$executeRawUnsafe(
      `INSERT INTO sbom_components (
         id,
         scan_run_id, name, version, purl, ecosystem,
         licenses, component_type, scope, is_dev_only,
         manifest_file, discovery_method, evidence_line,
         llm_evidence, cpe
       )
       SELECT
         gen_random_uuid(),
         $1::uuid, sc.name, sc.version, sc.purl, sc.ecosystem,
         sc.licenses, sc.component_type, sc.scope, sc.is_dev_only,
         sc.manifest_file,
         COALESCE(src.discovery_method, sc.discovery_method, 'manifest'),
         sc.evidence_line, sc.llm_evidence, sc.cpe
       FROM scope_components sc
       INNER JOIN scan_run_components src ON src.scope_component_id = sc.id
         AND src.scan_run_id = $1::uuid
       WHERE sc.id = $2::uuid
       ON CONFLICT (scan_run_id, purl) DO NOTHING`,
      scanRunId,
      sc.id,
    );

    // Fetch the sbom_components row (the one we just ensured exists).
    const sbomRow = await prisma.sbomComponent.findFirst({
      where: { scanRunId, purl: sc.purl, name: sc.name },
    });

    if (sbomRow) {
      rebuilt.push(sbomRow);
    }
  }

  logger.info(
    { scanRunId, scopeId, rebuilt: rebuilt.length, scopeRows: scopeRows.length },
    "[scopeComponentService] rebuildComponentsFromScopeState complete",
  );

  return rebuilt;
}

// ---------------------------------------------------------------------------
// Materialize recovered components into per-scan sbom_components rows.
// ---------------------------------------------------------------------------

/**
 * After llmSbomRecheckService recovers components into scope_components, this
 * writes a per-scan SbomComponent row for each recovered component so:
 *
 *   1. The scan's audit trail (sbom_components, scan_runs.sbom_json consumers)
 *      reflects that the recovered component was part of this run's SBOM.
 *   2. The worker's in-memory `components` list can be extended so the
 *      downstream OSV / NVD / detection passes pick them up this run instead
 *      of only carrying forward stale prior-scan vuln data.
 *
 * Discovery method is set to "recheck_recovery" to distinguish these rows
 * from the augmentation pass output. Returns the new rows in Prisma's
 * canonical SbomComponent shape so the caller can append them directly.
 */
export async function materializeRecoveredComponents(
  recoveredScopeComponentIds: string[],
  scanRunId: string,
): Promise<SbomComponent[]> {
  if (recoveredScopeComponentIds.length === 0) return [];

  const scopeRows = await prisma.scopeComponent.findMany({
    where: { id: { in: recoveredScopeComponentIds } },
  });

  // createMany + skipDuplicates leans on the (scan_run_id, purl) unique index
  // added in 20260515090000. Two scope_components rows for the same purl
  // (legitimate during the transition window before the LLM merge phase has
  // collapsed naming/version variants) would otherwise produce a Prisma
  // P2002 here and abort the entire recheck recovery. With skipDuplicates,
  // the second create silently no-ops and the caller still gets all rows
  // from the post-create findMany below.
  await prisma.sbomComponent.createMany({
    data: scopeRows.map((sc) => ({
      scanRunId,
      name: sc.name,
      version: sc.version,
      purl: sc.purl,
      ecosystem: sc.ecosystem,
      licenses: sc.licenses,
      componentType: sc.componentType,
      scope: sc.scope,
      isDevOnly: sc.isDevOnly,
      manifestFile: sc.manifestFile,
      discoveryMethod: "recheck_recovery",
      evidenceLine: sc.evidenceLine,
      llmEvidence: sc.llmEvidence ?? undefined,
      cpe: sc.cpe,
    })),
    skipDuplicates: true,
  });

  // Re-fetch by (scan_run_id, purl) so the caller gets the canonical rows —
  // whether freshly created or already present from a sibling scope_component
  // sharing the same purl.
  const created = await prisma.sbomComponent.findMany({
    where: {
      scanRunId,
      purl: { in: scopeRows.map((sc) => sc.purl) },
    },
  });

  logger.info(
    { scanRunId, requested: scopeRows.length, materialized: created.length },
    "[scopeComponentService] materializeRecoveredComponents complete",
  );

  return created;
}
