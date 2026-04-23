-- AlterTable
ALTER TABLE "app_settings" ADD COLUMN     "llm_assistance_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "llm_triage_token_budget" INTEGER NOT NULL DEFAULT 50000,
ADD COLUMN     "reachability_cvss_threshold" DOUBLE PRECISION NOT NULL DEFAULT 7.0;

-- AlterTable
ALTER TABLE "scan_findings" ADD COLUMN     "confirmed_reachable" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "reachable_assessed_at" TIMESTAMPTZ(6),
ADD COLUMN     "reachable_model" TEXT,
ADD COLUMN     "reachable_reasoning" TEXT,
ADD COLUMN     "reachable_via_sast_fingerprint" TEXT;

-- AlterTable
ALTER TABLE "scan_runs" ADD COLUMN     "confirmed_reachable_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "llm_input_tokens" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "llm_output_tokens" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "llm_request_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "sast_finding_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "warnings" JSONB NOT NULL DEFAULT '[]';

-- CreateTable
CREATE TABLE "sast_findings" (
    "id" UUID NOT NULL,
    "scan_run_id" UUID NOT NULL,
    "scope_id" UUID NOT NULL,
    "org_id" UUID,
    "fingerprint" TEXT NOT NULL,
    "rule_id" TEXT NOT NULL,
    "rule_name" TEXT,
    "rule_message" TEXT,
    "cwe_ids" TEXT[],
    "severity" TEXT NOT NULL DEFAULT 'info',
    "file_path" TEXT NOT NULL,
    "start_line" INTEGER NOT NULL,
    "end_line" INTEGER,
    "snippet" TEXT,
    "triage_status" TEXT NOT NULL DEFAULT 'pending',
    "triage_confidence" DOUBLE PRECISION,
    "triage_reasoning" TEXT,
    "triage_model" TEXT,
    "triage_input_tokens" INTEGER,
    "triage_output_tokens" INTEGER,
    "suppressed_at" TIMESTAMPTZ(6),
    "suppressed_by_user_id" UUID,
    "suppressed_reason" TEXT,
    "detail_json" JSONB,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sast_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cve_knowledge" (
    "id" UUID NOT NULL,
    "osv_id" TEXT NOT NULL,
    "cve_id" TEXT,
    "ecosystem" TEXT NOT NULL,
    "package_name" TEXT NOT NULL,
    "vulnerable_functions" TEXT[],
    "extraction_method" TEXT NOT NULL,
    "extraction_confidence" DOUBLE PRECISION NOT NULL,
    "extraction_model" TEXT,
    "extraction_reasoning" TEXT,
    "osv_modified_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "cve_knowledge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sast_findings_fingerprint_idx" ON "sast_findings"("fingerprint");

-- CreateIndex
CREATE INDEX "sast_findings_scope_id_fingerprint_idx" ON "sast_findings"("scope_id", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "sast_findings_scan_run_id_fingerprint_key" ON "sast_findings"("scan_run_id", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "cve_knowledge_osv_id_key" ON "cve_knowledge"("osv_id");

-- CreateIndex
CREATE INDEX "cve_knowledge_ecosystem_package_name_idx" ON "cve_knowledge"("ecosystem", "package_name");

-- AddForeignKey
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_scan_run_id_fkey" FOREIGN KEY ("scan_run_id") REFERENCES "scan_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_scope_id_fkey" FOREIGN KEY ("scope_id") REFERENCES "scan_scopes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;
