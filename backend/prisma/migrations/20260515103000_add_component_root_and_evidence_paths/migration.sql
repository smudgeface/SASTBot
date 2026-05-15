-- Add component_root + evidence_paths to scope_components and sbom_components.
--
-- componentRoot is the stable identity for vendored components: the shallowest
-- directory path that exclusively belongs to this upstream library
-- (e.g. "extern/Xenomai"). It is more robust than evidence_path against the
-- LLM picking different specific files for the same library across scans.
--
-- evidencePaths is the diagnostic file list (headers, sources, READMEs, CMake
-- files, etc.) — surfaced in the Components UI panel for the operator to
-- click through. It does NOT participate in dedup.
--
-- Backfill:
--   - componentRoot = parent directory of evidencePath when set
--     (using POSIX-style split on the last '/'). Null for rows where
--     evidencePath is null.
--   - evidencePaths = ARRAY[evidencePath] when evidencePath is non-null.
--
-- evidence_path is retained for backwards compatibility; new writes populate
-- evidence_paths and leave evidence_path null. A future migration can drop
-- the column once all callers are converted.

ALTER TABLE scope_components
  ADD COLUMN component_root TEXT,
  ADD COLUMN evidence_paths TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE sbom_components
  ADD COLUMN component_root TEXT,
  ADD COLUMN evidence_paths TEXT[] NOT NULL DEFAULT '{}';

-- Backfill scope_components.
UPDATE scope_components
SET component_root = CASE
      WHEN evidence_path IS NULL THEN NULL
      WHEN position('/' in evidence_path) = 0 THEN evidence_path
      ELSE regexp_replace(evidence_path, '/[^/]+$', '')
    END,
    evidence_paths = CASE
      WHEN evidence_path IS NULL THEN '{}'::text[]
      ELSE ARRAY[evidence_path]
    END
WHERE evidence_path IS NOT NULL;

-- Helpful index for the componentMatch chain's Tier-1 lookup
-- (scope_id + component_root). Partial — most npm rows have a null root.
CREATE INDEX scope_components_scope_id_component_root_idx
  ON scope_components (scope_id, component_root)
  WHERE component_root IS NOT NULL;
