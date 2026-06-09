-- AlterTable
ALTER TABLE "scan_runs" ADD COLUMN     "llm_cache_read_tokens" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "llm_cache_write_tokens" INTEGER NOT NULL DEFAULT 0;
