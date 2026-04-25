-- AlterTable
ALTER TABLE "repos" ADD COLUMN     "llm_recheck_token_budget" INTEGER NOT NULL DEFAULT 50000,
ADD COLUMN     "llm_sast_token_budget" INTEGER NOT NULL DEFAULT 300000,
ADD COLUMN     "sast_engine" TEXT NOT NULL DEFAULT 'opengrep';

-- AlterTable
ALTER TABLE "sbom_components" ADD COLUMN     "discovery_method" TEXT DEFAULT 'manifest',
ADD COLUMN     "evidence_line" INTEGER;
