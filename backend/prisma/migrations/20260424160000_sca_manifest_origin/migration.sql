-- Capture the manifest file each SCA dependency comes from (e.g. package-lock.json)
-- plus the ±3-line snippet around the declaration. Mirrors the latest_file_path /
-- latest_start_line / latest_snippet trio on sast_issues.

ALTER TABLE "sbom_components"
  ADD COLUMN "manifest_file" TEXT;

ALTER TABLE "sca_issues"
  ADD COLUMN "latest_manifest_file"    TEXT,
  ADD COLUMN "latest_manifest_line"    INTEGER,
  ADD COLUMN "latest_manifest_snippet" TEXT;
