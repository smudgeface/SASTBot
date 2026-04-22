-- AlterTable
ALTER TABLE "credentials" ADD COLUMN     "expires_at" TIMESTAMPTZ(6);

-- AlterTable
ALTER TABLE "scan_runs" ADD COLUMN     "component_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "critical_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "high_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "low_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "medium_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "sbom_json" JSONB;

-- CreateTable
CREATE TABLE "sbom_components" (
    "id" UUID NOT NULL,
    "scan_run_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "purl" TEXT NOT NULL,
    "ecosystem" TEXT,
    "licenses" TEXT[],
    "component_type" TEXT NOT NULL DEFAULT 'library',

    CONSTRAINT "sbom_components_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_findings" (
    "id" UUID NOT NULL,
    "scan_run_id" UUID NOT NULL,
    "component_id" UUID NOT NULL,
    "osv_id" TEXT NOT NULL,
    "cve_id" TEXT,
    "severity" TEXT NOT NULL DEFAULT 'unknown',
    "cvss_score" DOUBLE PRECISION,
    "cvss_vector" TEXT,
    "summary" TEXT,
    "aliases" TEXT[],
    "actively_exploited" BOOLEAN NOT NULL DEFAULT false,
    "detail_json" JSONB,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sbom_components_scan_run_id_idx" ON "sbom_components"("scan_run_id");

-- CreateIndex
CREATE INDEX "scan_findings_scan_run_id_idx" ON "scan_findings"("scan_run_id");

-- AddForeignKey
ALTER TABLE "sbom_components" ADD CONSTRAINT "sbom_components_scan_run_id_fkey" FOREIGN KEY ("scan_run_id") REFERENCES "scan_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_run_id_fkey" FOREIGN KEY ("scan_run_id") REFERENCES "scan_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_component_id_fkey" FOREIGN KEY ("component_id") REFERENCES "sbom_components"("id") ON DELETE CASCADE ON UPDATE CASCADE;
