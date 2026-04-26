-- AlterTable
ALTER TABLE "scan_runs" ADD COLUMN     "current_phase" TEXT,
ADD COLUMN     "phase_progress" JSONB;
