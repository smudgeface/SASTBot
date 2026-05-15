-- Normalize sentinel version strings ("unknown", "*", "") to NULL in both
-- per-scan and scope-level component tables.
--
-- Why this exists: the LLM augmentation pass sometimes emits the literal
-- string "unknown" instead of omitting the version field. The purl
-- synthesizer (applySbomAugmentation) then produces `pkg:generic/foo@unknown`
-- alongside the canonical `pkg:generic/foo`, and the resulting rows escape
-- the (scan_run_id, purl) unique index added in the previous migration.
-- Symptom: 7 component name-pairs surviving the prior dedup pass on FSS
-- (gridctrl, heidenhain-eib7-sdk, labjack-ljm, libpcap, mesa, moxa-mxio,
-- yaffs2), each appearing twice in the Components UI.
--
-- The matching Zod transform in llmSbomService.ts prevents new rows from
-- being created in this state; this migration cleans up existing rows.
--
-- Strategy:
--   1. For each table, find rows whose version is a sentinel string AND
--      a sibling row exists in the same scope (scan_run_id or scope_id) with
--      the same name and a normalized version. Re-point references from the
--      sentinel row to the sibling, then delete the sentinel row.
--   2. For sentinel rows with no sibling, UPDATE in place: version → NULL,
--      and strip the trailing "@..." segment from the purl so future scans
--      emitting the normalized form match via the existing identity chain.

-- ─────────────────────────────────────────────────────────────────────────
-- Part A: sbom_components
-- ─────────────────────────────────────────────────────────────────────────

-- A.1: Consolidate paired rows. Re-point scan_findings.component_id from
-- the sentinel row to the canonical sibling, then delete the sentinel.
WITH sentinels AS (
  SELECT id, scan_run_id, name
  FROM sbom_components
  WHERE version IS NOT NULL
    AND LOWER(TRIM(version)) IN ('unknown', '*', '')
),
pairs AS (
  SELECT DISTINCT ON (s.id)
    s.id AS sentinel_id,
    sc.id AS canonical_id
  FROM sentinels s
  JOIN sbom_components sc
    ON sc.scan_run_id = s.scan_run_id
    AND sc.name = s.name
    AND sc.id <> s.id
    AND (sc.version IS NULL OR LOWER(TRIM(sc.version)) NOT IN ('unknown', '*', ''))
  ORDER BY s.id, sc.id
)
UPDATE scan_findings sf
SET component_id = p.canonical_id
FROM pairs p
WHERE sf.component_id = p.sentinel_id;

WITH sentinels AS (
  SELECT id, scan_run_id, name
  FROM sbom_components
  WHERE version IS NOT NULL
    AND LOWER(TRIM(version)) IN ('unknown', '*', '')
),
pairs AS (
  SELECT DISTINCT ON (s.id) s.id AS sentinel_id
  FROM sentinels s
  JOIN sbom_components sc
    ON sc.scan_run_id = s.scan_run_id
    AND sc.name = s.name
    AND sc.id <> s.id
    AND (sc.version IS NULL OR LOWER(TRIM(sc.version)) NOT IN ('unknown', '*', ''))
  ORDER BY s.id, sc.id
)
DELETE FROM sbom_components WHERE id IN (SELECT sentinel_id FROM pairs);

-- A.2: Normalize solo sentinel rows in place. The purl regex strips a
-- trailing "@<segment>" — safe because synthesized purls only ever end in
-- `@<version>` (no qualifiers, no subpaths from our synthesizer) and the
-- `[^/@]+$` anchor prevents over-stripping on npm scoped packages whose
-- name segment legitimately contains `@`.
UPDATE sbom_components
SET version = NULL,
    purl = regexp_replace(purl, '@[^/@]+$', '')
WHERE version IS NOT NULL
  AND LOWER(TRIM(version)) IN ('unknown', '*', '');

-- ─────────────────────────────────────────────────────────────────────────
-- Part B: scope_components (same shape, different join table)
-- ─────────────────────────────────────────────────────────────────────────

-- B.1: Re-point scan_run_components from sentinel to canonical sibling,
-- then delete the sentinel scope_components row. ON CONFLICT DO NOTHING
-- handles the case where the canonical sibling already has a join row for
-- the same scan_run_id.
WITH sentinels AS (
  SELECT id, scope_id, name
  FROM scope_components
  WHERE version IS NOT NULL
    AND LOWER(TRIM(version)) IN ('unknown', '*', '')
),
pairs AS (
  SELECT DISTINCT ON (s.id)
    s.id AS sentinel_id,
    sc.id AS canonical_id
  FROM sentinels s
  JOIN scope_components sc
    ON sc.scope_id = s.scope_id
    AND sc.name = s.name
    AND sc.id <> s.id
    AND (sc.version IS NULL OR LOWER(TRIM(sc.version)) NOT IN ('unknown', '*', ''))
  ORDER BY s.id, sc.id
)
INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
SELECT DISTINCT ON (src.scan_run_id, p.canonical_id)
  src.scan_run_id, p.canonical_id, src.discovery_method
FROM scan_run_components src
JOIN pairs p ON p.sentinel_id = src.scope_component_id
ORDER BY src.scan_run_id, p.canonical_id, src.discovery_method
ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING;

WITH sentinels AS (
  SELECT id, scope_id, name
  FROM scope_components
  WHERE version IS NOT NULL
    AND LOWER(TRIM(version)) IN ('unknown', '*', '')
),
pairs AS (
  SELECT DISTINCT ON (s.id) s.id AS sentinel_id
  FROM sentinels s
  JOIN scope_components sc
    ON sc.scope_id = s.scope_id
    AND sc.name = s.name
    AND sc.id <> s.id
    AND (sc.version IS NULL OR LOWER(TRIM(sc.version)) NOT IN ('unknown', '*', ''))
  ORDER BY s.id, sc.id
)
DELETE FROM scope_components WHERE id IN (SELECT sentinel_id FROM pairs);

-- B.2: Normalize solo sentinel rows in place.
UPDATE scope_components
SET version = NULL,
    purl = regexp_replace(purl, '@[^/@]+$', '')
WHERE version IS NOT NULL
  AND LOWER(TRIM(version)) IN ('unknown', '*', '');
