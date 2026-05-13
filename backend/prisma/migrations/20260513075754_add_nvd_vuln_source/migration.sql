-- AlterTable
ALTER TABLE "app_settings" ADD COLUMN     "nvd_credential_id" UUID;

-- AlterTable
ALTER TABLE "sbom_components" ADD COLUMN     "cpe" TEXT;

-- AlterTable
ALTER TABLE "sca_issues" ADD COLUMN     "source" TEXT NOT NULL DEFAULT 'osv';

-- AddForeignKey
ALTER TABLE "app_settings" ADD CONSTRAINT "app_settings_nvd_credential_id_fkey" FOREIGN KEY ("nvd_credential_id") REFERENCES "credentials"("id") ON DELETE SET NULL ON UPDATE CASCADE;
