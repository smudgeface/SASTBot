-- Per-repo LLM token-budget overrides (Stream D, production-readiness plan).
--
-- Four nullable INT columns on repos. NULL means "use the worker's compiled-in
-- default" (200k / 50k / 300k / 50k for SBOM aug / SBOM recheck / SAST
-- detection / SAST recheck respectively). A non-null value overrides that
-- default for this specific repo — useful when a codebase is unusually large
-- (raise the cap) or trivially small (lower it to cut cost).
--
-- Replacing the previous non-nullable llm_sast_token_budget (default 300000)
-- and llm_recheck_token_budget (default 50000) with nullable equivalents, and
-- adding the two new SBOM columns. Existing rows get NULL (= keep using the
-- worker default) which is semantically equivalent to the old hardcoded default.

-- Drop the old default constraints on the two columns that existed before.
ALTER TABLE repos
  ALTER COLUMN llm_sast_token_budget DROP DEFAULT,
  ALTER COLUMN llm_sast_token_budget DROP NOT NULL,
  ALTER COLUMN llm_recheck_token_budget DROP DEFAULT,
  ALTER COLUMN llm_recheck_token_budget DROP NOT NULL;

-- NULL-out existing rows so NULL is the canonical "use default" signal.
UPDATE repos SET llm_sast_token_budget = NULL WHERE llm_sast_token_budget IS NOT NULL;
UPDATE repos SET llm_recheck_token_budget = NULL WHERE llm_recheck_token_budget IS NOT NULL;

-- Add the two new SBOM-pass columns (both nullable, no default).
ALTER TABLE repos
  ADD COLUMN IF NOT EXISTS llm_sbom_token_budget INT,
  ADD COLUMN IF NOT EXISTS llm_sbom_recheck_token_budget INT;
