-- AlterTable
ALTER TABLE "sbom_components" ADD COLUMN     "occurrences" JSONB NOT NULL DEFAULT '[]';
