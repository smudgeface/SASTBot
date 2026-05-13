-- CreateTable
CREATE TABLE "scope_components" (
    "id" UUID NOT NULL,
    "scope_id" UUID NOT NULL,
    "org_id" UUID,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "purl" TEXT NOT NULL,
    "ecosystem" TEXT,
    "licenses" TEXT[],
    "component_type" TEXT NOT NULL DEFAULT 'library',
    "scope" TEXT,
    "is_dev_only" BOOLEAN NOT NULL DEFAULT false,
    "manifest_file" TEXT,
    "discovery_method" TEXT DEFAULT 'manifest',
    "evidence_line" INTEGER,
    "evidence_path" TEXT,
    "llm_evidence" JSONB,
    "cpe" TEXT,
    "source" TEXT NOT NULL DEFAULT 'scan',
    "dismissed_status" TEXT NOT NULL DEFAULT 'active',
    "dismissed_reason" TEXT,
    "dismissed_at" TIMESTAMPTZ(6),
    "first_seen_scan_run_id" UUID,
    "last_seen_scan_run_id" UUID,
    "last_seen_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "scope_components_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_run_components" (
    "scan_run_id" UUID NOT NULL,
    "scope_component_id" UUID NOT NULL,
    "discovery_method" TEXT NOT NULL,

    CONSTRAINT "scan_run_components_pkey" PRIMARY KEY ("scan_run_id","scope_component_id")
);

-- CreateIndex
CREATE INDEX "scope_components_scope_id_dismissed_status_idx" ON "scope_components"("scope_id", "dismissed_status");

-- CreateIndex
CREATE UNIQUE INDEX "scope_components_scope_id_name_version_purl_key" ON "scope_components"("scope_id", "name", "version", "purl");

-- AddForeignKey
ALTER TABLE "scope_components" ADD CONSTRAINT "scope_components_scope_id_fkey" FOREIGN KEY ("scope_id") REFERENCES "scan_scopes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_run_components" ADD CONSTRAINT "scan_run_components_scan_run_id_fkey" FOREIGN KEY ("scan_run_id") REFERENCES "scan_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_run_components" ADD CONSTRAINT "scan_run_components_scope_component_id_fkey" FOREIGN KEY ("scope_component_id") REFERENCES "scope_components"("id") ON DELETE CASCADE ON UPDATE CASCADE;
