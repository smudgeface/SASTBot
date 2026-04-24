-- Per-repo URL template for linking file paths in SAST/SCA details.
-- Users put $FILE and $LINE placeholders, e.g.
--   https://git.example.com/projects/PROJ/repos/REPO/browse/$FILE#$LINE

ALTER TABLE "repos" ADD COLUMN "source_url_template" TEXT;
