-- Dedup sbom_components per (scan_run_id, purl) and enforce uniqueness.
--
-- Bug: rebuildComponentsFromScopeState (scopeComponentService.ts) inserts
-- one sbom_components row per active scope_component after a merge, with
-- `ON CONFLICT DO NOTHING`. The clause is a no-op because sbom_components
-- had no unique constraint other than the PK, so every call duplicated
-- rows whose `(scan_run_id, purl)` already existed. Affected every scan
-- whose SBOM recheck phase produced at least one merge verdict.
--
-- Symptom: Components tab showed ~2× the real count. Operator-visible on
-- FSS scope `/` after scan 8a678392 — 33 active scope_components but 68
-- sbom_components rows for the scan, with names like xenomai / cuda-runtime
-- appearing twice with identical purl, name, version, cpe, and discovery
-- method.
--
-- This migration:
--   1. Re-points `scan_findings.component_id` from non-canonical sbom_components
--      rows to the canonical (lowest-id) row per (scan_run_id, purl). FK is
--      ON DELETE CASCADE so we have to re-point before deleting; otherwise the
--      cascade would silently drop legitimate findings.
--   2. Deletes the non-canonical sbom_components rows.
--   3. Adds a unique index on (scan_run_id, purl). After this, the existing
--      `ON CONFLICT (scan_run_id, purl) DO NOTHING` (paired code change in
--      rebuildComponentsFromScopeState) becomes effective.

-- Step 1: re-point scan_findings references onto the canonical row.
-- DISTINCT ON picks the smallest id per (scan_run_id, purl). PostgreSQL has
-- no MIN(uuid), so we sort-and-pick instead of aggregating.
WITH canonical AS (
  SELECT DISTINCT ON (scan_run_id, purl)
    scan_run_id, purl, id AS canonical_id
  FROM sbom_components
  ORDER BY scan_run_id, purl, id
)
UPDATE scan_findings sf
SET component_id = c.canonical_id
FROM sbom_components sc
JOIN canonical c
  ON c.scan_run_id = sc.scan_run_id
  AND c.purl = sc.purl
WHERE sf.component_id = sc.id
  AND sc.id <> c.canonical_id;

-- Step 2: delete the non-canonical sbom_components rows.
WITH canonical AS (
  SELECT DISTINCT ON (scan_run_id, purl)
    scan_run_id, purl, id AS canonical_id
  FROM sbom_components
  ORDER BY scan_run_id, purl, id
)
DELETE FROM sbom_components sc
USING canonical c
WHERE sc.scan_run_id = c.scan_run_id
  AND sc.purl = c.purl
  AND sc.id <> c.canonical_id;

-- Step 3: enforce uniqueness going forward.
CREATE UNIQUE INDEX sbom_components_scan_run_id_purl_unique
  ON sbom_components (scan_run_id, purl);
