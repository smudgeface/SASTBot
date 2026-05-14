-- AlterTable
ALTER TABLE "repos" ADD COLUMN     "llm_sbom_recheck_effort" TEXT NOT NULL DEFAULT 'medium';
