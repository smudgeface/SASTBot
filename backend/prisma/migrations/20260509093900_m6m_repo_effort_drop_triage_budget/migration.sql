-- M6m: per-repo, per-phase effort levels for `claude -p --effort` + drop
-- the orphan llm_triage_token_budget (the legacy llmTriageService it gated
-- was removed in M6g; nothing has read this column since).

ALTER TABLE "repos"
  ADD COLUMN "llm_sast_effort"    TEXT NOT NULL DEFAULT 'xhigh',
  ADD COLUMN "llm_recheck_effort" TEXT NOT NULL DEFAULT 'medium';

ALTER TABLE "app_settings"
  DROP COLUMN "llm_triage_token_budget";
