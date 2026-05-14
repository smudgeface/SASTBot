-- Dedup scope_components rows that share the same evidence_path within a scope.
--
-- The LLM augmentation pass picks a slightly different canonical name for the
-- same vendored library each run (e.g. "Thorlabs SDK" / "thorlabs-sdk" /
-- "thorlabs-motion-control"), so without a stronger identity key the
-- scope_components table accumulates a new row per name variant per scan.
-- evidence_path IS the canonical identity — a vendored library lives at one
-- specific path inside extern/. Two rows with the same (scope_id,
-- evidence_path) are the same conceptual component.
--
-- This migration:
--   1. Collapses each (scope_id, evidence_path) duplicate group into the
--      oldest row (first-seen wins for stable naming).
--   2. For each scan_run that had a join row pointing at a dropped row,
--      ensure a matching join row exists pointing at the kept row instead
--      (INSERT ... ON CONFLICT DO NOTHING handles the case where both
--      already coexist).
--   3. Deletes all join rows that still point at dropped scope_components.
--   4. Deletes the duplicate scope_components rows.
--   5. Adds a partial unique index so future runs cannot re-introduce the
--      problem at the DB level.
--
-- Rows with evidence_path = NULL are left alone — without a path key we
-- cannot safely assert they are duplicates.

-- Step 1: build the (keep_id, drop_id) pairs into a temp table.
CREATE TEMP TABLE _scope_dedup_pairs AS
WITH groups AS (
  SELECT
    scope_id,
    evidence_path,
    array_agg(id ORDER BY created_at ASC, id ASC) AS ids
  FROM scope_components
  WHERE evidence_path IS NOT NULL
  GROUP BY scope_id, evidence_path
  HAVING COUNT(*) > 1
)
SELECT
  ids[1] AS keep_id,
  unnest(ids[2:array_length(ids, 1)]) AS drop_id
FROM groups;

-- Step 2: for each (scan_run, drop_id) join row, ensure a (scan_run,
-- keep_id) row exists. Using INSERT ... ON CONFLICT DO NOTHING avoids the
-- iterative-UPDATE conflict that arises when multiple drop_ids in the same
-- scan map to the same keep_id (the first UPDATE would create the row, the
-- second would PK-conflict). DISTINCT ON picks one discovery_method per
-- target row deterministically.
INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
SELECT DISTINCT ON (src.scan_run_id, d.keep_id)
  src.scan_run_id,
  d.keep_id,
  src.discovery_method
FROM scan_run_components src
JOIN _scope_dedup_pairs d ON src.scope_component_id = d.drop_id
ORDER BY src.scan_run_id, d.keep_id, src.discovery_method
ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING;

-- Step 3: delete all join rows pointing at any drop_id. Their information
-- has been preserved via the keep_id rows.
DELETE FROM scan_run_components
WHERE scope_component_id IN (SELECT drop_id FROM _scope_dedup_pairs);

-- Step 4: delete the duplicate scope_components rows.
DELETE FROM scope_components
WHERE id IN (SELECT drop_id FROM _scope_dedup_pairs);

DROP TABLE _scope_dedup_pairs;

-- Step 5: add the partial unique index so future inserts can't re-introduce
-- the problem. Postgres treats NULL as not-equal-to-NULL, so the WHERE
-- clause makes this enforce uniqueness only over rows that have a non-null
-- evidence_path.
CREATE UNIQUE INDEX scope_components_evidence_path_unique
  ON scope_components (scope_id, evidence_path)
  WHERE evidence_path IS NOT NULL;
