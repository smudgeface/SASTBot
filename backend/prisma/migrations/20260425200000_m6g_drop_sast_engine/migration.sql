-- M6g: drop the sast_engine column. Opengrep code paths were removed in
-- the same commit; the LLM-driven SAST pipeline is now the only path, so
-- there is no per-repo engine choice to persist.
ALTER TABLE "repos" DROP COLUMN "sast_engine";
