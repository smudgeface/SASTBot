-- AlterTable
ALTER TABLE "repos" ADD COLUMN     "first_party_namespaces" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "llm_sbom_effort" TEXT NOT NULL DEFAULT 'medium',
ADD COLUMN     "vendored_dirs" TEXT[] DEFAULT ARRAY['extern/', 'third-party/', 'vendor/']::TEXT[];

-- AlterTable
ALTER TABLE "sbom_components" ADD COLUMN     "llm_evidence" JSONB;
