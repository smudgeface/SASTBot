-- AlterTable: remove llm_assistance_enabled from app_settings
ALTER TABLE "app_settings" DROP COLUMN IF EXISTS "llm_assistance_enabled";

-- AlterTable: add latest_llm_summary to sast_issues
ALTER TABLE "sast_issues" ADD COLUMN IF NOT EXISTS "latest_llm_summary" TEXT;

-- AlterTable: add latest_llm_summary to sca_issues
ALTER TABLE "sca_issues" ADD COLUMN IF NOT EXISTS "latest_llm_summary" TEXT;
