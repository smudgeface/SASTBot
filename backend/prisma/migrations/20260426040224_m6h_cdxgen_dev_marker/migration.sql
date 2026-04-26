-- AlterTable
ALTER TABLE "sbom_components" ADD COLUMN     "is_dev_only" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "sca_issues" ADD COLUMN     "latest_is_dev_only" BOOLEAN NOT NULL DEFAULT false;
