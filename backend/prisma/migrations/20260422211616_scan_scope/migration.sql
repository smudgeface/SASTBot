-- CreateTable: scan_scopes
CREATE TABLE "scan_scopes" (
    "id" UUID NOT NULL,
    "org_id" UUID,
    "repo_id" UUID NOT NULL,
    "path" TEXT NOT NULL DEFAULT '/',
    "display_name" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_scopes_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "scan_scopes_repo_id_path_key" ON "scan_scopes"("repo_id", "path");

ALTER TABLE "scan_scopes" ADD CONSTRAINT "scan_scopes_org_id_fkey"
  FOREIGN KEY ("org_id") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "scan_scopes" ADD CONSTRAINT "scan_scopes_repo_id_fkey"
  FOREIGN KEY ("repo_id") REFERENCES "repos"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Seed one default scope per existing repo (path = '/')
INSERT INTO "scan_scopes" ("id", "org_id", "repo_id", "path", "created_at")
SELECT gen_random_uuid(), "org_id", "id", '/', "created_at"
FROM "repos";

-- AlterTable: add scope_id as nullable first so existing rows can be backfilled
ALTER TABLE "scan_runs" ADD COLUMN "scope_id" UUID;

-- Backfill: every existing scan_run points to its repo's default scope
UPDATE "scan_runs" sr
SET "scope_id" = ss."id"
FROM "scan_scopes" ss
WHERE ss."repo_id" = sr."repo_id" AND ss."path" = '/';

-- Now enforce NOT NULL (all rows are filled)
ALTER TABLE "scan_runs" ALTER COLUMN "scope_id" SET NOT NULL;

ALTER TABLE "scan_runs" ADD CONSTRAINT "scan_runs_scope_id_fkey"
  FOREIGN KEY ("scope_id") REFERENCES "scan_scopes"("id") ON DELETE CASCADE ON UPDATE CASCADE;
