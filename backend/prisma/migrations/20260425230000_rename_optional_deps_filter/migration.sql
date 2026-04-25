-- Rename and re-default the optional-deps filter:
--   * "dev_deps" was misleading — cdxgen also lumps transitive runtime deps
--     into CycloneDX `scope: "optional"`, so the column controls more than
--     just devDependencies.
--   * Default flips false → true. The earlier default risked false-negative
--     reachability verdicts on transitive runtime CVEs (verified case:
--     requirejs on Gocator /GoWeb).
ALTER TABLE "repos" RENAME COLUMN "reachability_include_dev_deps"
                              TO "reachability_include_optional_deps";
ALTER TABLE "repos" ALTER COLUMN "reachability_include_optional_deps"
                    SET DEFAULT true;
-- Existing rows were created under the prior default (false). Bring them in
-- line with the new default since the prior value was based on a wrong
-- understanding of cdxgen scope semantics. Operators who want to opt out
-- can flip it off via the Repo edit form.
UPDATE "repos" SET "reachability_include_optional_deps" = true
              WHERE "reachability_include_optional_deps" = false;
