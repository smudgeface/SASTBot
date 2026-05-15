-- Backfill scope_components.evidence_paths from sbom_components.occurrences.
--
-- The scope page's Components tab previously rendered file locations from
-- BOTH `occurrences` (per-scan, pulled forward from sbom_components on
-- read) and `evidence_paths` (scope-level, M7). The two sets overlapped and
-- caused confusion: Boost showed "Found in (1 location)" but Evidence "root:
-- (not set)".
--
-- This migration consolidates: for every scope_component whose
-- evidence_paths is empty, copy the file paths from the matching
-- sbom_components row (joined via lastSeenScanRunId + purl) into
-- evidence_paths. After this runs, the UI can drop the per-scan
-- `occurrences` fetch and render everything from scope_components.
--
-- component_root is deliberately NOT auto-derived here — operators want to
-- review/edit each one via the PATCH endpoint and inline edit UI.

WITH paths_from_occ AS (
  SELECT
    sc.id AS scope_component_id,
    array_agg(DISTINCT occ.value->>'path') FILTER (
      WHERE occ.value->>'path' IS NOT NULL AND occ.value->>'path' <> ''
    ) AS paths
  FROM scope_components sc
  JOIN sbom_components s
    ON s.scan_run_id = sc.last_seen_scan_run_id
    AND s.purl = sc.purl
  CROSS JOIN LATERAL jsonb_array_elements(s.occurrences::jsonb) AS occ
  WHERE sc.last_seen_scan_run_id IS NOT NULL
    AND (array_length(sc.evidence_paths, 1) IS NULL OR array_length(sc.evidence_paths, 1) = 0)
  GROUP BY sc.id
)
UPDATE scope_components sc
SET evidence_paths = pfo.paths
FROM paths_from_occ pfo
WHERE sc.id = pfo.scope_component_id
  AND pfo.paths IS NOT NULL
  AND array_length(pfo.paths, 1) > 0;
