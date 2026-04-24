-- Rename SCA dismissed_status values to match SAST triageStatus vocabulary
UPDATE "sca_issues" SET "dismissed_status" = 'pending' WHERE "dismissed_status" = 'active';
UPDATE "sca_issues" SET "dismissed_status" = 'suppressed' WHERE "dismissed_status" = 'wont_fix';
UPDATE "sca_issues" SET "dismissed_status" = 'suppressed' WHERE "dismissed_status" = 'acknowledged';

-- Change default from 'active' to 'pending'
ALTER TABLE "sca_issues" ALTER COLUMN "dismissed_status" SET DEFAULT 'pending';
