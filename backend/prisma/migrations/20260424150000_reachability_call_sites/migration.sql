-- Capture the LLM's structured output for reachability:
--   confidence  — float in [0,1] returned by the model
--   call_sites  — list of {file, line, snippet} the model identified as triggers

ALTER TABLE "sca_issues"
  ADD COLUMN "reachable_confidence" DOUBLE PRECISION,
  ADD COLUMN "reachable_call_sites" JSONB;
