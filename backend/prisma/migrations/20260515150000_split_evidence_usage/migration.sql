-- Split "evidence" vs "usage" on scope_components.
--
-- Why: the M7 jsonb `evidence` column ended up holding "usage" data — the
-- long list of import/include sites where cdxgen saw the component
-- referenced — not "evidence" in the SBOM/CRA sense (the verifiable
-- identity proof). The user-facing model the operator needs is:
--   - evidence (small): WHERE the analyzer concluded the component is
--     present. For manifest-tracked packages: {lockfile path + line +
--     snippet of the lockfile entry}. For vendored libraries: just the
--     shallowest unique directory.
--   - usage (long): WHERE the component is imported/included from. No
--     snippets — clickable file:line is enough.
--
-- This migration adds the usage column, moves the existing (mislabeled)
-- evidence data to it, and resets evidence to identity-shape using
-- columns we already populate (component_root, manifest_file). The
-- per-row snippet field on manifest evidence is left null here and
-- filled in by the next worker boot via backfillScopeComponentEvidenceSnippets.

ALTER TABLE scope_components
  ADD COLUMN IF NOT EXISTS usage JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 1. Preserve currently-visible data: move evidence → usage. Skip rows
--    that are empty / non-array so we don't clobber a fresh default.
UPDATE scope_components
SET usage = evidence
WHERE jsonb_typeof(evidence) = 'array'
  AND jsonb_array_length(evidence) > 0;

-- 2. Reset evidence to identity-shape. Three cases, in priority order:
--      a. component_root set (vendored library) → root path only.
--      b. manifest_file set (manifest-tracked package) → manifest path with
--         line:null, snippet:null. The worker-boot backfill resolves both
--         on next start.
--      c. neither set → empty array.
--    Operator-curated rows (source='manual_override') are left alone —
--    if the operator deliberately put paths/lines in evidence via the
--    PATCH endpoint, we trust them.
UPDATE scope_components
SET evidence = CASE
  WHEN component_root IS NOT NULL AND component_root <> ''
    THEN jsonb_build_array(jsonb_build_object('path', component_root))
  WHEN manifest_file IS NOT NULL AND manifest_file <> ''
    THEN jsonb_build_array(jsonb_build_object('path', manifest_file))
  ELSE '[]'::jsonb
END
WHERE source <> 'manual_override';

-- sbom_components keeps its existing shape:
--   - sbom_components.occurrences (jsonb) — usage data, per-scan.
--   - sbom_components.evidence (jsonb) — identity, per-scan. Currently
--     empty for cdxgen-survivor rows; the worker's persistAugmentedComponents
--     starts populating it with manifest_file/component_root identity rows
--     going forward. No migration needed here — historical scan-page audit
--     views already render `occurrences` for usage and the empty `evidence`
--     column just degrades gracefully.
