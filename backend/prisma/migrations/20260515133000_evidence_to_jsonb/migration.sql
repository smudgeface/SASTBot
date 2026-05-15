-- Convert `evidence_paths` (text[]) to `evidence` (jsonb) on scope_components
-- and sbom_components. Each existing path becomes a {path} object; line
-- numbers are added later by future scans / manual edits.
--
-- Why: the flat text[] discarded line-number information that's useful for
-- triage on manifest-tracked packages (npm, pypi, maven, nuget) — the line
-- in `package-lock.json` where a dependency is declared. `<FileLink>` in the
-- UI already supports `$LINE` in the source-URL template, so the click-
-- through to git is free once we carry the line.
--
-- The data lives at the boundary of LLM emissions and the existing
-- per-scan `occurrences` extractor — both already produce {path, line}
-- shapes.

ALTER TABLE scope_components
  ADD COLUMN evidence JSONB NOT NULL DEFAULT '[]';

ALTER TABLE sbom_components
  ADD COLUMN evidence JSONB NOT NULL DEFAULT '[]';

-- Backfill scope_components.evidence from evidence_paths.
UPDATE scope_components
SET evidence = COALESCE(
  (
    SELECT jsonb_agg(jsonb_build_object('path', p))
    FROM unnest(evidence_paths) AS p
    WHERE p IS NOT NULL AND p <> ''
  ),
  '[]'::jsonb
)
WHERE array_length(evidence_paths, 1) IS NOT NULL;

-- Backfill sbom_components.evidence from evidence_paths.
UPDATE sbom_components
SET evidence = COALESCE(
  (
    SELECT jsonb_agg(jsonb_build_object('path', p))
    FROM unnest(evidence_paths) AS p
    WHERE p IS NOT NULL AND p <> ''
  ),
  '[]'::jsonb
)
WHERE array_length(evidence_paths, 1) IS NOT NULL;

-- Drop the legacy text[] columns.
ALTER TABLE scope_components DROP COLUMN evidence_paths;
ALTER TABLE sbom_components DROP COLUMN evidence_paths;
