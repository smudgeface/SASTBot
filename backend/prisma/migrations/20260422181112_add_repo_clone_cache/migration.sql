-- AlterTable
ALTER TABLE "repos" ADD COLUMN     "last_cloned_at" TIMESTAMPTZ(6),
ADD COLUMN     "retain_clone" BOOLEAN NOT NULL DEFAULT false;
