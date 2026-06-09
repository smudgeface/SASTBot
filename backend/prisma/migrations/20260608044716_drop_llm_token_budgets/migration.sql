-- AlterTable: per-pass LLM token budgets removed (v0.25.0). The model self-paces;
-- the wall-clock cap is the runaway backstop. Progress is reported as token counts.
ALTER TABLE "repos" DROP COLUMN "llm_sbom_token_budget",
DROP COLUMN "llm_sbom_recheck_token_budget",
DROP COLUMN "llm_sast_token_budget",
DROP COLUMN "llm_recheck_token_budget";
