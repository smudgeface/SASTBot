-- Per-repo ignore-paths list. Paths declared here are excluded from every
-- scope's scan, regardless of nesting. Combined with the existing scope
-- exclusions logic so an ignore path under a scope's tree is dropped at
-- scan time. JSONB array of path strings; default empty.

ALTER TABLE "repos"
  ADD COLUMN "ignore_paths" JSONB NOT NULL DEFAULT '[]';
