-- Replace the numeric reachability threshold with a severity dropdown.
-- Severity is what users think in; the prior CVSS score field paired badly
-- with our data (most OSV advisories supply only a vector, not a numeric score).

ALTER TABLE "app_settings" ADD COLUMN "reachability_min_severity" TEXT NOT NULL DEFAULT 'high';
ALTER TABLE "app_settings" DROP COLUMN "reachability_cvss_threshold";
