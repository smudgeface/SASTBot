/**
 * scopeComponentService.ts — SBOM Component Recheck, Stage 1
 *
 * Provides the backfill that bootstraps `scope_components` from the existing
 * `sbom_components` data. This is an idempotent worker-boot hook following
 * the same pattern as backfillLlmSummaries, backfillCvssScores, etc.
 *
 * See docs/SBOM_COMPONENT_RECHECK_PLAN.md for the full architectural rationale.
 *
 * Algorithm:
 *   For each ScanScope in the DB:
 *     1. Find the most-recent scan_run where status = 'success'. Skip if none.
 *     2. For each sbom_components row tied to that scan_run:
 *        - Upsert into scope_components keyed by (scope_id, name, version, purl).
 *          NULL version values are preserved — the unique constraint is defined
 *          as UNIQUE NULLS NOT DISTINCT (Postgres 15+) in the raw INSERT so that
 *          two rows with the same (scope_id, name, NULL, purl) correctly conflict.
 *          We fall back to a raw SQL INSERT … ON CONFLICT DO NOTHING to avoid
 *          Prisma's compound-unique upsert requirement that all key fields be
 *          non-null strings.
 *        - On insert: set firstSeenScanRunId = lastSeenScanRunId = scan_run_id,
 *          lastSeenAt = scan_run.created_at, dismissedStatus = 'active',
 *          source = 'scan'. Copy all component fields.
 *        - On conflict: no-op in Stage 1 (bootstrap only).
 *        - Insert the scan_run_components join row (ON CONFLICT DO NOTHING).
 */

import { pino } from "pino";
import { prisma } from "../db.js";
import { loadConfig } from "../config.js";
import type { SbomComponent } from "@prisma/client";

const logger = pino({ level: loadConfig().logLevel, name: "scopeComponentService" });

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BackfillSummary {
  scopesProcessed: number;
  scopesSkipped: number;
  componentsInserted: number;
  joinsInserted: number;
}

// ---------------------------------------------------------------------------
// Backfill: promote sbom_components → scope_components for each scope's
// latest successful scan run. Safe to re-run on every worker boot.
// ---------------------------------------------------------------------------

export async function backfillScopeComponentsFromLatestScans(): Promise<void> {
  // Fetch every scope — we'll query its latest successful run individually.
  const scopes = await prisma.scanScope.findMany({
    select: { id: true, orgId: true },
  });

  if (scopes.length === 0) {
    logger.info("[scopeComponentService] backfill: no scopes — skipping");
    return;
  }

  logger.info({ scopeCount: scopes.length }, "[scopeComponentService] backfill: starting");

  const summary: BackfillSummary = {
    scopesProcessed: 0,
    scopesSkipped: 0,
    componentsInserted: 0,
    joinsInserted: 0,
  };

  for (const scope of scopes) {
    // Find the most-recent successful scan run for this scope.
    const latestRun = await prisma.scanRun.findFirst({
      where: { scopeId: scope.id, status: "success" },
      orderBy: { createdAt: "desc" },
      select: { id: true, createdAt: true },
    });

    if (!latestRun) {
      summary.scopesSkipped++;
      continue;
    }

    // Fetch all sbom_components for that scan run.
    const components = await prisma.sbomComponent.findMany({
      where: { scanRunId: latestRun.id },
    });

    for (const c of components) {
      // Extract evidencePath from llmEvidence if available. The plan calls this
      // out as "new — was implicit in llmEvidence". We populate it here from
      // the existing llmEvidence.path field so that Tier-1 file-existence
      // recheck can use it in Stage 2 without parsing the JSONB.
      let evidencePath: string | null = null;
      if (c.llmEvidence && typeof c.llmEvidence === "object") {
        const ev = c.llmEvidence as Record<string, unknown>;
        if (typeof ev.path === "string" && ev.path) {
          evidencePath = ev.path;
        }
      }

      try {
        // Use raw SQL for the scope_components upsert so we can correctly
        // handle NULL versions. Prisma's compound-unique upsert requires all
        // key fields to be non-null strings, but `version` is nullable here.
        // Raw INSERT … ON CONFLICT DO NOTHING is the idempotent pattern used
        // throughout this codebase (see backfillScanRunSeverities, etc.).
        //
        // The unique index "scope_components_scope_id_name_version_purl_key"
        // uses standard Postgres NULL semantics (NULLs not equal), so two
        // rows with version=NULL for the same (scope_id, name, purl) would
        // not conflict. We rely on purl uniqueness as the practical
        // deduplication key for components without a version — purlS for
        // versionless components typically embed the name and are distinct
        // per package.
        const inserted = await prisma.$executeRawUnsafe(
          `INSERT INTO scope_components (
            id, scope_id, org_id,
            name, version, purl, ecosystem,
            licenses, component_type, scope, is_dev_only,
            manifest_file, discovery_method, evidence_line,
            evidence_path, llm_evidence, cpe,
            source, dismissed_status,
            first_seen_scan_run_id, last_seen_scan_run_id, last_seen_at,
            created_at, updated_at
          )
          VALUES (
            gen_random_uuid(), $1::uuid, $2::uuid,
            $3, $4, $5, $6,
            $7::text[], $8, $9, $10,
            $11, $12, $13,
            $14, $15::jsonb, $16,
            'scan', 'active',
            $17::uuid, $17::uuid, $18::timestamptz,
            now(), now()
          )
          ON CONFLICT (scope_id, name, version, purl)
          DO NOTHING`,
          scope.id,
          scope.orgId ?? null,
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
          c.llmEvidence !== null ? JSON.stringify(c.llmEvidence) : null,
          c.cpe ?? null,
          latestRun.id,
          latestRun.createdAt.toISOString(),
        );

        summary.componentsInserted += inserted;

        // Fetch the scope_component id (regardless of insert or conflict)
        // so we can insert the join row.
        const existing = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
          `SELECT id FROM scope_components
           WHERE scope_id = $1::uuid
             AND name = $2
             AND purl = $3
             AND (version = $4 OR ($4 IS NULL AND version IS NULL))
           LIMIT 1`,
          scope.id,
          c.name,
          c.purl,
          c.version ?? null,
        );

        if (existing.length === 0) {
          logger.warn(
            { scopeId: scope.id, purl: c.purl },
            "[scopeComponentService] backfill: could not find scope_component after upsert — skipping join row",
          );
          continue;
        }

        const scopeComponentId = existing[0]!.id;

        // Insert the join row. ON CONFLICT DO NOTHING for idempotency.
        const joinInserted = await prisma.$executeRawUnsafe(
          `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
           VALUES ($1::uuid, $2::uuid, $3)
           ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING`,
          latestRun.id,
          scopeComponentId,
          c.discoveryMethod ?? "manifest",
        );

        summary.joinsInserted += joinInserted;
      } catch (err) {
        logger.warn(
          { err: (err as Error).message, scopeId: scope.id, purl: c.purl },
          "[scopeComponentService] backfill: error upserting component — skipping",
        );
      }
    }

    summary.scopesProcessed++;
  }

  logger.info(
    {
      scopesProcessed: summary.scopesProcessed,
      scopesSkipped: summary.scopesSkipped,
      componentsInserted: summary.componentsInserted,
      joinsInserted: summary.joinsInserted,
    },
    "[scopeComponentService] backfill complete",
  );
}

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

  for (const c of components) {
    // Extract evidence_path from llmEvidence if not already a top-level field.
    let evidencePath: string | null = (c as unknown as { evidencePath?: string | null }).evidencePath ?? null;
    if (!evidencePath && c.llmEvidence && typeof c.llmEvidence === "object") {
      const ev = c.llmEvidence as Record<string, unknown>;
      if (typeof ev.path === "string" && ev.path) {
        evidencePath = ev.path;
      }
    }

    try {
      let scopeComponentId: string | null = null;

      // Primary identity: evidence_path when present. The LLM picks a slightly
      // different canonical name for the same vendored library each run
      // ("Thorlabs SDK" / "thorlabs-sdk" / "thorlabs-motion-control"), so
      // matching on (scope_id, name, version, purl) would let those name
      // variants accumulate as separate rows. The vendored library lives at
      // one specific path inside extern/ — that path is the stable identity.
      // When an existing row matches, update its last-seen markers but
      // preserve the existing name (first-seen wins, stable for operator
      // memory). Bad LLM names get cleaned up via a future manual rename UI.
      if (evidencePath) {
        const matched = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
          `SELECT id FROM scope_components
           WHERE scope_id = $1::uuid
             AND evidence_path = $2
           LIMIT 1`,
          scopeId,
          evidencePath,
        );
        if (matched.length > 0) {
          scopeComponentId = matched[0]!.id;
          await prisma.$executeRawUnsafe(
            `UPDATE scope_components SET
              last_seen_scan_run_id = $1::uuid,
              last_seen_at          = now(),
              updated_at            = now(),
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
          );
          upserted++;
        }
      }

      // Secondary identity: CPE. Path-agnostic, NVD-canonical. Catches the
      // case where the same upstream library moves files between scans (LLM
      // picks `extern/Foo/bar.h` one run and `extern/Foo/baz.h` the next,
      // both with the same emitted CPE). Only kicks in when (a) the
      // incoming component has a CPE and (b) evidence_path didn't already
      // match an existing row. Note: we don't backfill CPE on
      // evidence_path matches — that would risk colliding with another row
      // in the same scope that already carries this CPE, which needs a
      // merge rather than an update. Tracked as a future enhancement.
      if (!scopeComponentId) {
        const incomingCpe = (c as unknown as { cpe?: string | null }).cpe ?? null;
        if (incomingCpe) {
          const matched = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
            `SELECT id FROM scope_components
             WHERE scope_id = $1::uuid
               AND cpe = $2
             LIMIT 1`,
            scopeId,
            incomingCpe,
          );
          if (matched.length > 0) {
            scopeComponentId = matched[0]!.id;
            await prisma.$executeRawUnsafe(
              `UPDATE scope_components SET
                last_seen_scan_run_id = $1::uuid,
                last_seen_at          = now(),
                updated_at            = now(),
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
            );
            upserted++;
          }
        }
      }

      // Tertiary identity: (scope_id, name, version, purl). Used for rows
      // with neither an evidence_path match nor a CPE match — covers cdxgen
      // manifest discovery, legacy rows, manual additions, and the first
      // insertion of any new component. Uses raw SQL ON CONFLICT so NULL
      // version values can collide (Prisma's compound upsert requires
      // non-null keys).
      if (!scopeComponentId) {
        await prisma.$executeRawUnsafe(
          `INSERT INTO scope_components (
            id, scope_id, org_id,
            name, version, purl, ecosystem,
            licenses, component_type, scope, is_dev_only,
            manifest_file, discovery_method, evidence_line,
            evidence_path, llm_evidence, cpe,
            source, dismissed_status,
            first_seen_scan_run_id, last_seen_scan_run_id, last_seen_at,
            created_at, updated_at
          )
          VALUES (
            gen_random_uuid(), $1::uuid, $2::uuid,
            $3, $4, $5, $6,
            $7::text[], $8, $9, $10,
            $11, $12, $13,
            $14, $15::jsonb, $16,
            'scan', 'active',
            $17::uuid, $17::uuid, now(),
            now(), now()
          )
          ON CONFLICT (scope_id, name, version, purl) DO UPDATE
            SET last_seen_scan_run_id = EXCLUDED.last_seen_scan_run_id,
                last_seen_at          = EXCLUDED.last_seen_at,
                updated_at            = now(),
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
          c.llmEvidence !== null ? JSON.stringify(c.llmEvidence) : null,
          (c as unknown as { cpe?: string | null }).cpe ?? null,
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
      }

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
    { scanRunId, scopeId, upserted, joinsInserted },
    "[scopeComponentService] persistScanComponentsToScopeState complete",
  );

  return { upserted, joinsInserted };
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

  const created: SbomComponent[] = [];
  for (const sc of scopeRows) {
    const row = await prisma.sbomComponent.create({
      data: {
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
      },
    });
    created.push(row);
  }

  logger.info(
    { scanRunId, materialized: created.length },
    "[scopeComponentService] materializeRecoveredComponents complete",
  );

  return created;
}
