-- AlterTable: promote SBOM-relevant fields onto scope_components so the
-- scope-level curated SBOM endpoint (GET /api/scopes/:id/sbom-json) can
-- derive the document entirely from scope_components without reading the
-- per-scan sbom_components table (closes M9 finding F1 / F6).

ALTER TABLE "scope_components"
  ADD COLUMN "latest_licenses"         TEXT[]   NOT NULL DEFAULT '{}',
  ADD COLUMN "latest_cpe"              TEXT,
  ADD COLUMN "latest_component_type"   TEXT,
  ADD COLUMN "latest_discovery_method" TEXT,
  ADD COLUMN "latest_llm_evidence"     JSONB;

-- Backfill: join each active scope_component to its most recent matching
-- sbom_components row via (lastSeenScanRunId, name, version, purl).
-- This is best-effort — unmatched rows stay NULL and will be populated
-- on the next scan run when persistScanComponentsToScopeState writes them.
UPDATE scope_components sc
SET
  latest_licenses         = sb.licenses,
  latest_cpe              = sb.cpe,
  latest_component_type   = sb.component_type,
  latest_discovery_method = sb.discovery_method,
  latest_llm_evidence     = sb.llm_evidence::jsonb
FROM sbom_components sb
WHERE sb.scan_run_id = sc.last_seen_scan_run_id
  AND lower(sb.name)    = lower(sc.name)
  AND (sb.version       IS NOT DISTINCT FROM sc.version)
  AND (sb.purl          IS NOT DISTINCT FROM sc.purl)
  AND sc.dismissed_status = 'active';
