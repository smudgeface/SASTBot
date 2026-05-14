-- Secondary dedup for scope_components by CPE.
--
-- The evidence_path migration (20260514130500) collapsed same-path duplicates.
-- This migration handles the remaining case: cross-path duplicates where the
-- LLM emitted a consistent CPE but picked a different evidence file in the
-- same vendor directory across runs. CPE is the canonical NVD identifier —
-- two rows with the same (scope_id, cpe) refer to the same upstream library
-- regardless of which file the LLM happened to point at.
--
-- This migration:
--   1. For each (scope_id, cpe) duplicate group where cpe IS NOT NULL,
--      picks a canonical row preferring richer-information rows (has
--      evidence_path > has version > oldest created_at).
--   2. Re-points scan_run_components.scope_component_id from dropped to kept.
--   3. Deletes duplicate join rows then duplicate scope_components rows.
--   4. Adds a partial unique index on (scope_id, cpe) WHERE cpe IS NOT NULL
--      so future inserts can't re-introduce the collision.
--
-- Rows with cpe = NULL are left alone — the LLM didn't know a CPE for them
-- (typical for vendor SDKs not in NVD's dictionary), so no identity claim.

CREATE TEMP TABLE _scope_cpe_dedup_pairs AS
WITH groups AS (
  SELECT
    scope_id,
    cpe,
    array_agg(
      id
      ORDER BY
        (evidence_path IS NULL) ASC,
        (version IS NULL) ASC,
        created_at ASC,
        id ASC
    ) AS ids
  FROM scope_components
  WHERE cpe IS NOT NULL
  GROUP BY scope_id, cpe
  HAVING COUNT(*) > 1
)
SELECT
  ids[1] AS keep_id,
  unnest(ids[2:array_length(ids, 1)]) AS drop_id
FROM groups;

-- For each (scan_run, drop_id) join row, ensure a (scan_run, keep_id) row
-- exists. DISTINCT ON + ON CONFLICT DO NOTHING handles the multi-drop-to-one-keep
-- case where the naive UPDATE pattern hits a PK conflict mid-statement.
INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
SELECT DISTINCT ON (src.scan_run_id, d.keep_id)
  src.scan_run_id,
  d.keep_id,
  src.discovery_method
FROM scan_run_components src
JOIN _scope_cpe_dedup_pairs d ON src.scope_component_id = d.drop_id
ORDER BY src.scan_run_id, d.keep_id, src.discovery_method
ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING;

DELETE FROM scan_run_components
WHERE scope_component_id IN (SELECT drop_id FROM _scope_cpe_dedup_pairs);

DELETE FROM scope_components
WHERE id IN (SELECT drop_id FROM _scope_cpe_dedup_pairs);

DROP TABLE _scope_cpe_dedup_pairs;

-- Partial unique index. NULL cpe rows are excluded — vendor SDKs not in NVD
-- can have null cpe and shouldn't be forced into uniqueness.
CREATE UNIQUE INDEX scope_components_cpe_unique
  ON scope_components (scope_id, cpe)
  WHERE cpe IS NOT NULL;
