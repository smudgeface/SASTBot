/**
 * scopeComponentService.ts — scope-level component state.
 *
 * The two exports of note:
 *   - `persistScanComponentsToScopeState`: the in-flight scan writer. Called
 *     after Stage 2 (LLM augmentation) by the worker. Uses the deterministic
 *     componentMatch chain to match each emitted sbom_component against
 *     existing scope_components, updating identity fields on match and
 *     inserting on miss.
 *   - `materializeRecoveredComponents`: scope-only; bumps lastSeenScanRunId
 *     on the scope_components rows that the recheck marked "still_present".
 *     After E1, this function no longer writes to sbom_components — the
 *     per-scan audit table is immutable post-ingest.
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
import { TERMINAL_SCA_STATUSES } from "./scaAutoFix.js";

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
 * - Existing 'active' or 'not_found' row hit: update lastSeenScanRunId,
 *   lastSeenAt. Flip 'not_found' back to 'active' (the component is back).
 * - Existing source='manual_override' row: leave dismissedStatus / reason as-is.
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
    // Evidence (identity) — small jsonb array of {path, line?, snippet?}.
    // Lifted directly from sbom_components.evidence which persistAugmentedComponents
    // now populates for both LLM-vendored (componentRoot only) and
    // cdxgen-survivor (manifest_file + line + snippet) rows.
    const rawEvidence = (c as unknown as { evidence?: unknown }).evidence;
    const evidenceArr: unknown[] = Array.isArray(rawEvidence) ? rawEvidence : [];
    const evidenceJson = JSON.stringify(evidenceArr);
    // Usage — long jsonb array of {path, line?} lifted from
    // sbom_components.occurrences. The scope-page detail panel renders this
    // as the "Usage" list (clickable file:line links).
    const rawOccurrences = (c as unknown as { occurrences?: unknown }).occurrences;
    const usageArr: unknown[] = Array.isArray(rawOccurrences) ? rawOccurrences : [];
    const usageJson = JSON.stringify(usageArr);
    // True when at least one incoming evidence entry has either a numeric
    // line or a non-empty snippet — gates the "refresh existing identity
    // when richer data arrives" branch of the upsert CASE so we don't churn
    // rows where the new payload is no richer than what's already there.
    const incomingEvidenceIsRicher = evidenceArr.some(
      (e) => e !== null && typeof e === "object" &&
        (typeof (e as { line?: unknown }).line === "number" ||
         (typeof (e as { snippet?: unknown }).snippet === "string" &&
          ((e as { snippet?: string }).snippet?.length ?? 0) > 0)),
    );
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
        // latest* fields always overwrite — they represent "what the latest
        // scan saw", not operator choices. No COALESCE.
        const latestLicensesArr = `{${c.licenses.map((l) => `"${l.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(",")}}`;
        const latestLlmEvidenceJson = c.llmEvidence !== null ? JSON.stringify(c.llmEvidence) : null;
        await prisma.$executeRawUnsafe(
          `UPDATE scope_components SET
            last_seen_scan_run_id    = $1::uuid,
            last_seen_at             = now(),
            updated_at               = now(),
            component_root = COALESCE(component_root, $3),
            evidence = CASE
              WHEN source = 'manual_override' THEN evidence
              WHEN evidence IS NULL OR jsonb_array_length(evidence) = 0
                THEN $4::jsonb
              WHEN $5::boolean
                AND NOT EXISTS (
                  SELECT 1 FROM jsonb_array_elements(evidence) AS e
                  WHERE (e->>'line') IS NOT NULL
                     OR ((e->>'snippet') IS NOT NULL AND length(e->>'snippet') > 0)
                )
                THEN $4::jsonb
              ELSE evidence
            END,
            usage = CASE
              WHEN source = 'manual_override' THEN usage
              ELSE $6::jsonb
            END,
            dismissed_status = CASE
              WHEN dismissed_status = 'not_found' THEN 'active'
              ELSE dismissed_status
            END,
            dismissed_reason = CASE
              WHEN dismissed_status = 'not_found' THEN NULL
              ELSE dismissed_reason
            END,
            dismissed_at = CASE
              WHEN dismissed_status = 'not_found' THEN NULL
              ELSE dismissed_at
            END,
            latest_licenses         = $7::text[],
            latest_cpe              = $8,
            latest_component_type   = $9,
            latest_discovery_method = $10,
            latest_llm_evidence     = $11::jsonb
          WHERE id = $2::uuid`,
          scanRunId,
          scopeComponentId,
          componentRoot ?? null,
          evidenceJson,
          incomingEvidenceIsRicher,
          usageJson,
          latestLicensesArr,
          incomingCpe ?? null,
          c.componentType ?? null,
          c.discoveryMethod ?? null,
          latestLlmEvidenceJson,
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
        const latestLicensesArr = `{${c.licenses.map((l) => `"${l.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(",")}}`;
        const latestLlmEvidenceJson = c.llmEvidence !== null ? JSON.stringify(c.llmEvidence) : null;
        await prisma.$executeRawUnsafe(
          `INSERT INTO scope_components (
            id, scope_id, org_id,
            name, version, purl, ecosystem,
            licenses, component_type, scope, is_dev_only,
            manifest_file, discovery_method, evidence_line,
            evidence_path, component_root, evidence,
            llm_evidence, cpe, usage,
            latest_licenses, latest_cpe, latest_component_type,
            latest_discovery_method, latest_llm_evidence,
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
            $17::jsonb, $18, $21::jsonb,
            $22::text[], $23, $24,
            $25, $26::jsonb,
            'scan', 'active',
            $19::uuid, $19::uuid, now(),
            now(), now()
          )
          ON CONFLICT (scope_id, name, version, purl) DO UPDATE
            SET last_seen_scan_run_id    = EXCLUDED.last_seen_scan_run_id,
                last_seen_at             = EXCLUDED.last_seen_at,
                updated_at               = now(),
                component_root           = COALESCE(scope_components.component_root, EXCLUDED.component_root),
                evidence = CASE
                  WHEN scope_components.source = 'manual_override' THEN scope_components.evidence
                  WHEN scope_components.evidence IS NULL OR jsonb_array_length(scope_components.evidence) = 0
                    THEN EXCLUDED.evidence
                  WHEN $20::boolean
                    AND NOT EXISTS (
                      SELECT 1 FROM jsonb_array_elements(scope_components.evidence) AS e
                      WHERE (e->>'line') IS NOT NULL
                         OR ((e->>'snippet') IS NOT NULL AND length(e->>'snippet') > 0)
                    )
                    THEN EXCLUDED.evidence
                  ELSE scope_components.evidence
                END,
                usage = CASE
                  WHEN scope_components.source = 'manual_override' THEN scope_components.usage
                  ELSE EXCLUDED.usage
                END,
                dismissed_status = CASE
                  WHEN scope_components.dismissed_status = 'not_found' THEN 'active'
                  ELSE scope_components.dismissed_status
                END,
                dismissed_reason = CASE
                  WHEN scope_components.dismissed_status = 'not_found' THEN NULL
                  ELSE scope_components.dismissed_reason
                END,
                dismissed_at = CASE
                  WHEN scope_components.dismissed_status = 'not_found' THEN NULL
                  ELSE scope_components.dismissed_at
                END,
                latest_licenses         = EXCLUDED.latest_licenses,
                latest_cpe              = EXCLUDED.latest_cpe,
                latest_component_type   = EXCLUDED.latest_component_type,
                latest_discovery_method = EXCLUDED.latest_discovery_method,
                latest_llm_evidence     = EXCLUDED.latest_llm_evidence`,
          scopeId,
          orgId ?? null,
          c.name,
          c.version ?? null,
          c.purl,
          c.ecosystem ?? null,
          `{${c.licenses.map((l) => `"${l.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(",")}}`,
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
          incomingEvidenceIsRicher,
          usageJson,
          latestLicensesArr,
          incomingCpe ?? null,
          c.componentType ?? null,
          c.discoveryMethod ?? null,
          latestLlmEvidenceJson,
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
// E1: Scope-only recovery — bump lastSeenScanRunId on recovered components.
// ---------------------------------------------------------------------------

/**
 * After llmSbomRecheckService marks components as "still_present" (recovered),
 * update scope_components.lastSeenScanRunId = scanRunId for each recovered row.
 *
 * E1: this is now scope-only — no sbom_components writes. The per-scan audit
 * table (sbom_components) is immutable after ingestSbomFromArtifact runs.
 * Downstream OSV / NVD passes use the ingest-produced rows (direct observations
 * only); recovered components carry forward via scope_components for future scans.
 *
 * Lockstep SCA recovery: a recovered component is still present, so its known
 * CVEs are still present too — they were just not re-queried this run (OSV/NVD
 * run against direct observations only, to save tokens). We therefore bump
 * `lastSeenScanRunId` on the component's still-open (non-terminal) SCA issues as
 * well. Without this, the later SCA auto-fix sweep — which marks any issue not
 * seen this run as `fixed` — would FALSELY resolve every CVE of a component the
 * scan just confirmed is present. Terminal issues (operator decisions / already
 * resolved) are left untouched so we never resurrect a real resolution.
 */
export async function materializeRecoveredComponents(
  recoveredScopeComponentIds: string[],
  scanRunId: string,
): Promise<{ updated: number; scaCarried: number }> {
  if (recoveredScopeComponentIds.length === 0) return { updated: 0, scaCarried: 0 };

  const now = new Date();
  // Identify the recovered components so we can match their SCA issues. SCA
  // issues link to components by (scopeId, packageName) — the same name-based
  // linkage the SBOM builder and the per-row "linked issues" UI use.
  const recovered = await prisma.scopeComponent.findMany({
    where: { id: { in: recoveredScopeComponentIds } },
    select: { scopeId: true, name: true },
  });

  await prisma.scopeComponent.updateMany({
    where: { id: { in: recoveredScopeComponentIds } },
    data: {
      lastSeenScanRunId: scanRunId,
      lastSeenAt: now,
    },
  });

  // Group recovered component names by scope (usually one scope per call) and
  // carry their open SCA issues forward in lockstep with the component.
  const namesByScope = new Map<string, Set<string>>();
  for (const r of recovered) {
    let set = namesByScope.get(r.scopeId);
    if (!set) { set = new Set(); namesByScope.set(r.scopeId, set); }
    set.add(r.name);
  }
  let scaCarried = 0;
  for (const [scopeId, names] of namesByScope) {
    const res = await prisma.scaIssue.updateMany({
      where: {
        scopeId,
        packageName: { in: [...names] },
        lastSeenScanRunId: { not: scanRunId },
        dismissedStatus: { notIn: TERMINAL_SCA_STATUSES },
      },
      data: { lastSeenScanRunId: scanRunId, lastSeenAt: now },
    });
    scaCarried += res.count;
  }

  logger.info(
    { scanRunId, updated: recoveredScopeComponentIds.length, scaCarried },
    "[scopeComponentService] materializeRecoveredComponents: scope_components + open SCA issues carried forward",
  );

  return { updated: recoveredScopeComponentIds.length, scaCarried };
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class ScopeComponentNotFoundError extends Error {
  constructor(componentId: string) {
    super(`ScopeComponent not found: ${componentId}`);
    this.name = "ScopeComponentNotFoundError";
  }
}

// ---------------------------------------------------------------------------
// Ignore / unignore — operator-facing soft-suppress
// ---------------------------------------------------------------------------

/**
 * Mark a scope_component as 'ignored' and cascade suppression to all
 * non-terminal sca_issues for the same package.
 *
 * Returns the number of sca_issue rows suppressed (for operator confirmation).
 */
export async function ignoreScopeComponent(
  componentId: string,
  reason?: string | null,
): Promise<{ suppressed_sca_count: number }> {
  return prisma.$transaction(async (tx) => {
    const component = await tx.scopeComponent.findUnique({
      where: { id: componentId },
      select: { id: true, scopeId: true, name: true },
    });
    if (!component) throw new ScopeComponentNotFoundError(componentId);

    await tx.scopeComponent.update({
      where: { id: componentId },
      data: {
        dismissedStatus: "ignored",
        dismissedReason: reason ?? null,
        dismissedAt: new Date(),
        updatedAt: new Date(),
      },
    });

    const result = await tx.$executeRaw`
      UPDATE sca_issues
      SET dismissed_status = 'suppressed',
          dismissed_reason = 'component_ignored',
          dismissed_at     = now(),
          updated_at       = now()
      WHERE scope_id = ${component.scopeId}::uuid
        AND package_name = ${component.name}
        AND dismissed_status NOT IN ('fixed', 'false_positive')
    `;

    logger.info(
      { componentId, scopeId: component.scopeId, name: component.name, suppressed_sca_count: result },
      "[scopeComponentService] ignoreScopeComponent: component ignored, sca_issues suppressed",
    );

    return { suppressed_sca_count: result };
  });
}

/**
 * Restore an 'ignored' scope_component to 'active' and un-suppress all
 * sca_issues that were cascaded by the ignore action.
 *
 * Only reverses issues suppressed with dismissed_reason='component_ignored'.
 * dev_tree_policy suppressions are left as-is.
 *
 * Returns the number of sca_issue rows restored.
 */
export async function unignoreScopeComponent(
  componentId: string,
): Promise<{ restored_sca_count: number }> {
  return prisma.$transaction(async (tx) => {
    const component = await tx.scopeComponent.findUnique({
      where: { id: componentId },
      select: { id: true, scopeId: true, name: true },
    });
    if (!component) throw new ScopeComponentNotFoundError(componentId);

    await tx.scopeComponent.update({
      where: { id: componentId },
      data: {
        dismissedStatus: "active",
        dismissedReason: null,
        dismissedAt: null,
        updatedAt: new Date(),
      },
    });

    const result = await tx.$executeRaw`
      UPDATE sca_issues
      SET dismissed_status = 'pending',
          dismissed_reason = NULL,
          dismissed_at     = NULL,
          updated_at       = now()
      WHERE scope_id = ${component.scopeId}::uuid
        AND package_name = ${component.name}
        AND dismissed_status = 'suppressed'
        AND dismissed_reason = 'component_ignored'
    `;

    logger.info(
      { componentId, scopeId: component.scopeId, name: component.name, restored_sca_count: result },
      "[scopeComponentService] unignoreScopeComponent: component restored, sca_issues un-suppressed",
    );

    return { restored_sca_count: result };
  });
}
