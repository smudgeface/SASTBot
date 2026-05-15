-- Restrict the evidence_path uniqueness constraint to generic-ecosystem rows.
--
-- The original index (20260514130500_dedup_scope_components_by_evidence_path)
-- enforced uniqueness over ALL rows with a non-null evidence_path. That
-- was correct for vendored C/C++ libraries (ecosystem = "generic"), where
-- the evidence_path points at a per-library file inside extern/ and is
-- effectively unique per upstream library. But it was wrong for manifest-
-- based ecosystems (npm, maven, pypi, nuget): every package in a single
-- package-lock.json shares the same evidence_path = "package-lock.json"
-- because that file IS their declaration source. The original index
-- forced dozens of legitimately distinct npm dependencies to collide.
--
-- Symptom: worker boot backfill flooded logs with PK conflict errors on
-- Gocator's /GoWeb (npm) scope:
--   "Key (scope_id, evidence_path)=(<scope>, GoEmulate/.../package.json)
--    already exists."
--
-- Fix: drop the unrestricted index, recreate with WHERE ecosystem = 'generic'.
-- For non-generic rows, fall back to the existing (scope_id, name, version,
-- purl) unique constraint which is the correct identity for manifest-tracked
-- packages. The corresponding Tier-1 lookup in persistScanComponentsToScopeState
-- is updated in the same commit to also gate on ecosystem = 'generic'.

DROP INDEX IF EXISTS scope_components_evidence_path_unique;

CREATE UNIQUE INDEX scope_components_evidence_path_unique
  ON scope_components (scope_id, evidence_path)
  WHERE evidence_path IS NOT NULL
    AND ecosystem = 'generic';
