-- One-off cleanup of existing duplicate scope_components rows.
--
-- The componentMatch chain (Tier 6: normalized-name + version equality) is
-- the strictest deterministic step that catches naming variants of the same
-- library. We mirror its predicate here to consolidate legacy duplicates
-- without touching components that componentMatch wouldn't merge anyway.
--
-- Mirrors normalizeName() in componentMatch.ts:
--   lowercase + strip [- _ \s] + drop leading "lib" prefix
-- Version equality: both NULL counts as equal; otherwise exact string match.
--
-- For each scope, group active rows by (normalized_name, version_key), pick
-- the lowest-id row as canonical, re-point scan_run_components from sibling
-- rows to it, then delete the siblings. Idempotent — re-running on a clean
-- DB is a no-op.
--
-- This deliberately does NOT merge by component_root alone: the backfill
-- heuristic (parent-dir-of-evidence_path) sometimes produces a shared root
-- for legitimately distinct libs (e.g. `extern/gettext/` bundles libiconv,
-- libexpat, WinSparkle as separate components). Forward emissions from the
-- LLM with proper "shallowest unique" roots will be cleaner — for legacy
-- rows we trust the name+version signal instead.

-- Helper: define the normalization inline because PG doesn't take user
-- functions easily inside a migration. The expression mirrors
-- normalizeName() in componentMatch.ts.
--
-- normalized_name = LOWER + strip [-_\s] + strip leading "lib"

WITH groups AS (
  SELECT
    scope_id,
    -- normalized name (matches componentMatch.normalizeName)
    regexp_replace(
      regexp_replace(LOWER(name), '[\s\-_]+', '', 'g'),
      '^lib',
      ''
    ) AS norm_name,
    COALESCE(TRIM(version), '') AS version_key,
    id,
    -- Pick canonical = lowest id per group.
    ROW_NUMBER() OVER (
      PARTITION BY
        scope_id,
        regexp_replace(
          regexp_replace(LOWER(name), '[\s\-_]+', '', 'g'),
          '^lib',
          ''
        ),
        COALESCE(TRIM(version), '')
      ORDER BY id
    ) AS rn
  FROM scope_components
  WHERE dismissed_status = 'active'
),
canonical AS (
  SELECT scope_id, norm_name, version_key, id AS canonical_id
  FROM groups
  WHERE rn = 1
),
duplicates AS (
  SELECT g.scope_id, g.norm_name, g.version_key, g.id AS dup_id, c.canonical_id
  FROM groups g
  JOIN canonical c USING (scope_id, norm_name, version_key)
  WHERE g.rn > 1
)
-- Step 1: re-point scan_run_components from duplicates to canonical rows.
-- ON CONFLICT DO NOTHING handles the case where the canonical row already
-- has a join entry for the same scan_run.
INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
SELECT DISTINCT ON (src.scan_run_id, d.canonical_id)
  src.scan_run_id,
  d.canonical_id,
  src.discovery_method
FROM duplicates d
JOIN scan_run_components src ON src.scope_component_id = d.dup_id
ORDER BY src.scan_run_id, d.canonical_id, src.discovery_method
ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING;

-- Step 2: delete the duplicate scope_components. CASCADE drops their
-- orphaned scan_run_components join rows automatically.
WITH groups AS (
  SELECT
    scope_id,
    regexp_replace(
      regexp_replace(LOWER(name), '[\s\-_]+', '', 'g'),
      '^lib',
      ''
    ) AS norm_name,
    COALESCE(TRIM(version), '') AS version_key,
    id,
    ROW_NUMBER() OVER (
      PARTITION BY
        scope_id,
        regexp_replace(
          regexp_replace(LOWER(name), '[\s\-_]+', '', 'g'),
          '^lib',
          ''
        ),
        COALESCE(TRIM(version), '')
      ORDER BY id
    ) AS rn
  FROM scope_components
  WHERE dismissed_status = 'active'
)
DELETE FROM scope_components
WHERE id IN (SELECT id FROM groups WHERE rn > 1);
