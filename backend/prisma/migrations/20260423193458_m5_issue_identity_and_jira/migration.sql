/*
  Warnings:

  - You are about to drop the column `suppressed_at` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `suppressed_by_user_id` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `suppressed_reason` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_confidence` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_input_tokens` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_model` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_output_tokens` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_reasoning` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `triage_status` on the `sast_findings` table. All the data in the column will be lost.
  - You are about to drop the column `confirmed_reachable` on the `scan_findings` table. All the data in the column will be lost.
  - You are about to drop the column `reachable_assessed_at` on the `scan_findings` table. All the data in the column will be lost.
  - You are about to drop the column `reachable_model` on the `scan_findings` table. All the data in the column will be lost.
  - You are about to drop the column `reachable_reasoning` on the `scan_findings` table. All the data in the column will be lost.
  - You are about to drop the column `reachable_via_sast_fingerprint` on the `scan_findings` table. All the data in the column will be lost.
  - Added the required column `issue_id` to the `sast_findings` table without a default value. This is not possible if the table is not empty.
  - Added the required column `issue_id` to the `scan_findings` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "app_settings" ADD COLUMN     "jira_email" TEXT;

-- AlterTable
ALTER TABLE "repos" ADD COLUMN     "last_scheduled_scan_at" TIMESTAMPTZ(6);

-- AlterTable
ALTER TABLE "sast_findings" DROP COLUMN "suppressed_at",
DROP COLUMN "suppressed_by_user_id",
DROP COLUMN "suppressed_reason",
DROP COLUMN "triage_confidence",
DROP COLUMN "triage_input_tokens",
DROP COLUMN "triage_model",
DROP COLUMN "triage_output_tokens",
DROP COLUMN "triage_reasoning",
DROP COLUMN "triage_status",
ADD COLUMN     "issue_id" UUID NOT NULL;

-- AlterTable
ALTER TABLE "scan_findings" DROP COLUMN "confirmed_reachable",
DROP COLUMN "reachable_assessed_at",
DROP COLUMN "reachable_model",
DROP COLUMN "reachable_reasoning",
DROP COLUMN "reachable_via_sast_fingerprint",
ADD COLUMN     "issue_id" UUID NOT NULL;

-- AlterTable
ALTER TABLE "scan_scopes" ADD COLUMN     "last_scan_completed_at" TIMESTAMPTZ(6),
ADD COLUMN     "last_scan_run_id" UUID;

-- CreateTable
CREATE TABLE "sast_issues" (
    "id" UUID NOT NULL,
    "org_id" UUID,
    "scope_id" UUID NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "triage_status" TEXT NOT NULL DEFAULT 'pending',
    "triage_confidence" DOUBLE PRECISION,
    "triage_reasoning" TEXT,
    "triage_model" TEXT,
    "triage_input_tokens" INTEGER,
    "triage_output_tokens" INTEGER,
    "suppressed_at" TIMESTAMPTZ(6),
    "suppressed_by_user_id" UUID,
    "suppressed_reason" TEXT,
    "notes" TEXT,
    "jira_ticket_id" UUID,
    "latest_rule_id" TEXT NOT NULL,
    "latest_rule_name" TEXT,
    "latest_rule_message" TEXT,
    "latest_severity" TEXT NOT NULL DEFAULT 'info',
    "latest_cwe_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "latest_file_path" TEXT NOT NULL,
    "latest_start_line" INTEGER NOT NULL,
    "latest_snippet" TEXT,
    "first_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "first_seen_scan_run_id" UUID NOT NULL,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_scan_run_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "sast_issues_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sca_issues" (
    "id" UUID NOT NULL,
    "org_id" UUID,
    "scope_id" UUID NOT NULL,
    "package_name" TEXT NOT NULL,
    "osv_id" TEXT NOT NULL,
    "dismissed_status" TEXT NOT NULL DEFAULT 'active',
    "dismissed_at" TIMESTAMPTZ(6),
    "dismissed_by_user_id" UUID,
    "dismissed_reason" TEXT,
    "notes" TEXT,
    "jira_ticket_id" UUID,
    "latest_package_version" TEXT,
    "latest_ecosystem" TEXT,
    "latest_component_scope" TEXT,
    "latest_finding_type" TEXT NOT NULL DEFAULT 'cve',
    "latest_cve_id" TEXT,
    "latest_severity" TEXT NOT NULL DEFAULT 'unknown',
    "latest_cvss_score" DOUBLE PRECISION,
    "latest_cvss_vector" TEXT,
    "latest_summary" TEXT,
    "latest_aliases" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "latest_actively_exploited" BOOLEAN NOT NULL DEFAULT false,
    "latest_eol_date" TIMESTAMPTZ(6),
    "latest_has_fix" BOOLEAN NOT NULL DEFAULT false,
    "confirmed_reachable" BOOLEAN NOT NULL DEFAULT false,
    "reachable_via_sast_fingerprint" TEXT,
    "reachable_reasoning" TEXT,
    "reachable_assessed_at" TIMESTAMPTZ(6),
    "reachable_model" TEXT,
    "reachable_at_scan_run_id" UUID,
    "first_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "first_seen_scan_run_id" UUID NOT NULL,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_scan_run_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "sca_issues_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "jira_tickets" (
    "id" UUID NOT NULL,
    "org_id" UUID,
    "issue_key" TEXT NOT NULL,
    "issue_id" TEXT,
    "project_key" TEXT,
    "project_name" TEXT,
    "summary" TEXT,
    "status" TEXT,
    "status_category" TEXT,
    "assignee_name" TEXT,
    "assignee_email" TEXT,
    "fix_versions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "issue_type" TEXT,
    "url" TEXT,
    "resolved_at" TIMESTAMPTZ(6),
    "last_synced_at" TIMESTAMPTZ(6),
    "sync_error" TEXT,
    "linked_by_user_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "jira_tickets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sast_issues_scope_id_triage_status_idx" ON "sast_issues"("scope_id", "triage_status");

-- CreateIndex
CREATE INDEX "sast_issues_scope_id_latest_severity_idx" ON "sast_issues"("scope_id", "latest_severity");

-- CreateIndex
CREATE INDEX "sast_issues_jira_ticket_id_idx" ON "sast_issues"("jira_ticket_id");

-- CreateIndex
CREATE UNIQUE INDEX "sast_issues_scope_id_fingerprint_key" ON "sast_issues"("scope_id", "fingerprint");

-- CreateIndex
CREATE INDEX "sca_issues_scope_id_latest_severity_idx" ON "sca_issues"("scope_id", "latest_severity");

-- CreateIndex
CREATE INDEX "sca_issues_scope_id_dismissed_status_idx" ON "sca_issues"("scope_id", "dismissed_status");

-- CreateIndex
CREATE INDEX "sca_issues_jira_ticket_id_idx" ON "sca_issues"("jira_ticket_id");

-- CreateIndex
CREATE UNIQUE INDEX "sca_issues_scope_id_package_name_osv_id_key" ON "sca_issues"("scope_id", "package_name", "osv_id");

-- CreateIndex
CREATE INDEX "jira_tickets_org_id_status_category_idx" ON "jira_tickets"("org_id", "status_category");

-- CreateIndex
CREATE UNIQUE INDEX "jira_tickets_org_id_issue_key_key" ON "jira_tickets"("org_id", "issue_key");

-- CreateIndex
CREATE INDEX "repos_is_active_schedule_cron_idx" ON "repos"("is_active", "schedule_cron");

-- CreateIndex
CREATE INDEX "scan_runs_scope_id_created_at_idx" ON "scan_runs"("scope_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "scan_runs_repo_id_created_at_idx" ON "scan_runs"("repo_id", "created_at" DESC);

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_issue_id_fkey" FOREIGN KEY ("issue_id") REFERENCES "sca_issues"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_issue_id_fkey" FOREIGN KEY ("issue_id") REFERENCES "sast_issues"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_issues" ADD CONSTRAINT "sast_issues_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_issues" ADD CONSTRAINT "sast_issues_scope_id_fkey" FOREIGN KEY ("scope_id") REFERENCES "scan_scopes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sast_issues" ADD CONSTRAINT "sast_issues_jira_ticket_id_fkey" FOREIGN KEY ("jira_ticket_id") REFERENCES "jira_tickets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sca_issues" ADD CONSTRAINT "sca_issues_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sca_issues" ADD CONSTRAINT "sca_issues_scope_id_fkey" FOREIGN KEY ("scope_id") REFERENCES "scan_scopes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sca_issues" ADD CONSTRAINT "sca_issues_jira_ticket_id_fkey" FOREIGN KEY ("jira_ticket_id") REFERENCES "jira_tickets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "jira_tickets" ADD CONSTRAINT "jira_tickets_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;
