-- AlterTable
ALTER TABLE "scan_findings" ADD COLUMN     "eol_date" TIMESTAMPTZ(6),
ADD COLUMN     "finding_type" TEXT NOT NULL DEFAULT 'cve';
