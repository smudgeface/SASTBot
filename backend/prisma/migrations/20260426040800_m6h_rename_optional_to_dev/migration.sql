-- Rename column to reflect its new semantics. The previous name
-- (reachability_include_optional_deps) referred to cdxgen's CycloneDX
-- `scope: "optional"` value, which conflated devDeps with transitive runtime
-- deps and was therefore not a clean dev/runtime classifier. cdxgen 12.2+
-- emits a real npm dev marker (cdx:npm:package:development), so the column
-- now controls whether *truly* dev-only deps (sbom_components.is_dev_only)
-- are included in the reachability hint set.
ALTER TABLE "repos"
  RENAME COLUMN "reachability_include_optional_deps" TO "reachability_include_dev_deps";
