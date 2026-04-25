-- Per-repo opt-in: include dev/optional cdxgen-scope components in the LLM
-- reachability hint set. Default off so reachability-enabled repos get a
-- runtime-only hint list, dropping the dev-tooling noise that dominated
-- the /GoWeb run (most "not reachable" verdicts hit webpack-dev-server,
-- babel-traverse, terser, and similar build-only deps).
ALTER TABLE "repos" ADD COLUMN "reachability_include_dev_deps" BOOLEAN NOT NULL DEFAULT false;
