-- Rename repos.reachability_include_dev_deps -> repos.include_dev_deps.
-- The flag governs far more than reachability (OSV/NVD scanning, SCA hints,
-- GUI default visibility, SBOM recheck, and the curated SBOM artifact), so the
-- "reachability" prefix was misleading. Hand-written as a RENAME (not Prisma's
-- default DROP+ADD) so existing per-repo values are preserved.
ALTER TABLE "repos" RENAME COLUMN "reachability_include_dev_deps" TO "include_dev_deps";
