/**
 * sastIngest.ts — file-first SAST ingest for per-scan artifact pipeline (Stream E2).
 *
 * Reads the SARIF artifact written by the worker's sarif_emit phase and upserts
 * sast_issues rows from it. This is the single DB write path for SAST findings;
 * the SARIF file is the canonical immutable record.
 *
 * Idempotent: calling ingestSastFromArtifact twice on the same file produces the
 * same row set. Re-running on the same file will call upsertSastIssueFromDetection
 * again, which does a proper upsert — same fingerprint → same row, no duplicates.
 *
 * After ingest the per-scan sast_issues set is authoritative. The recheck phase
 * then mutates triage-status fields on these rows (scope-level lifecycle) — it
 * does NOT re-emit or re-read the SARIF file.
 */

import { prisma } from "../db.js";
import { sarifPathFor, tryReadArtifact } from "./artifactStore.js";
import { upsertSastIssueFromDetection } from "./issueService.js";
import { computeAbsenceFingerprint, computeSastFingerprint } from "./llmSastService.js";

// ---------------------------------------------------------------------------
// Types for the SARIF document shape we parse back
// ---------------------------------------------------------------------------

interface SarifResultProperties {
  "sastbot:file_path_scope_relative"?: string;
  "sastbot:llm_summary"?: string;
  "sastbot:triage_confidence"?: string;
  "sastbot:absence_evidence_file"?: string;
  "sastbot:absence_evidence_line"?: string;
  severity?: string;
  [key: string]: unknown;
}

interface SarifResultLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: { startLine?: number; endLine?: number };
    contextRegion?: { snippet?: { text?: string } };
  };
}

interface SarifResult {
  ruleId?: string;
  kind?: string;
  level?: string;
  message?: { text?: string };
  locations?: SarifResultLocation[];
  properties?: SarifResultProperties;
}

interface SarifRuleRelationship {
  target?: { id?: string; toolComponent?: { name?: string } };
  kinds?: string[];
}

interface SarifReportingDescriptor {
  id: string;
  relationships?: SarifRuleRelationship[];
}

interface SarifRun {
  tool?: { driver?: { rules?: SarifReportingDescriptor[] } };
  results?: SarifResult[];
}

interface SarifDoc {
  runs?: SarifRun[];
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/**
 * Read ${ARTIFACT_DIR}/sarif/<scanRunId>.sarif.json and upsert sast_issues.
 * Sets lastSeenScanRunId=scanRunId on every matched issue.
 * Idempotent — re-running on the same file produces the same row set.
 */
export async function ingestSastFromArtifact(input: {
  scanRunId: string;
  scopeId: string;
  orgId: string | null;
  scopeDir: string;
  scopePath: string;
}): Promise<{ inserted: number; updated: number }> {
  const { scanRunId, scopeId, orgId, scopeDir } = input;

  // 1. Read SARIF file.
  const buf = await tryReadArtifact(sarifPathFor(scanRunId));
  if (!buf) {
    throw new Error(`sast_ingest: no SARIF artifact found for scan ${scanRunId}`);
  }

  let doc: SarifDoc;
  try {
    doc = JSON.parse(buf.toString("utf8")) as SarifDoc;
  } catch (err) {
    throw new Error(
      `sast_ingest: SARIF artifact for scan ${scanRunId} is not valid JSON: ${(err as Error).message}`,
    );
  }

  const run = doc.runs?.[0];
  if (!run) {
    throw new Error(`sast_ingest: SARIF artifact for scan ${scanRunId} has no runs[]`);
  }

  // 2. Build a rule → CWE ids map from the driver rules for extraction.
  const ruleCweMap = new Map<string, string[]>();
  for (const rule of run.tool?.driver?.rules ?? []) {
    const cwes: string[] = [];
    for (const rel of rule.relationships ?? []) {
      if (rel.target?.id && rel.target?.toolComponent?.name === "CWE") {
        cwes.push(`CWE-${rel.target.id}`);
      }
    }
    ruleCweMap.set(rule.id, cwes);
  }

  let inserted = 0;
  let updated = 0;

  // 3. Process each result.
  for (const result of run.results ?? []) {
    const ruleId = result.ruleId ?? "llm:UNKNOWN";
    const props = result.properties ?? {};
    const severity = props.severity ?? "info";
    const llmSummary = props["sastbot:llm_summary"] ?? undefined;
    const triageConfidenceRaw = props["sastbot:triage_confidence"];
    const triageConfidence = triageConfidenceRaw !== undefined ? parseFloat(triageConfidenceRaw as string) : 0.5;
    const cweIds = ruleCweMap.get(ruleId) ?? [];

    const isAbsence = result.kind === "informational" && !result.locations?.length;

    let fingerprint: string;
    let filePath: string;
    let startLine: number;
    let endLine: number | null;
    let snippet: string | null;

    if (isAbsence) {
      // Derive CWE from ruleId ("llm:CWE-N:absence" → "CWE-N").
      const absenceCwe = cweIds[0] ?? ruleId.replace(/^llm:/, "").replace(/:absence$/, "");
      fingerprint = computeAbsenceFingerprint(absenceCwe);
      const evidenceFile = (props["sastbot:absence_evidence_file"] as string | undefined) ?? "";
      const evidenceLineRaw = props["sastbot:absence_evidence_line"];
      const evidenceLine = evidenceLineRaw !== undefined ? parseInt(evidenceLineRaw as string, 10) : 0;
      filePath = evidenceFile;
      startLine = evidenceLine;
      endLine = null;
      snippet = `__absence__:${absenceCwe}`;
    } else {
      // SAST result — extract location from physicalLocation.
      const loc = result.locations?.[0];
      const region = loc?.physicalLocation?.region;
      startLine = region?.startLine ?? 0;
      endLine = region?.endLine && region.endLine !== startLine ? region.endLine : null;
      snippet = loc?.physicalLocation?.contextRegion?.snippet?.text ?? null;

      // The scope-relative path is stored in sastbot:* properties for fingerprint.
      const scopeRelPath = (props["sastbot:file_path_scope_relative"] as string | undefined) ?? "";

      fingerprint = await computeSastFingerprint(
        scopeDir,
        scopeRelPath,
        startLine,
        snippet ?? "",
      );

      // The filePath stored in DB is repo-rooted (from artifactLocation.uri).
      filePath = loc?.physicalLocation?.artifactLocation?.uri ?? scopeRelPath;
    }

    const { isNew } = await upsertSastIssueFromDetection(prisma, scanRunId, scopeId, orgId, {
      fingerprint,
      ruleId,
      ruleName: null,
      ruleMessage: (result.message?.text ?? llmSummary) ?? ruleId,
      severity: severity as string,
      cweIds,
      filePath,
      startLine,
      endLine,
      snippet,
    });

    // Stamp llmSummary and triageConfidence — upsertSastIssueFromDetection doesn't
    // accept these fields, so we update them separately (mirrors the worker's
    // existing pattern at worker.ts:367–380).
    if (llmSummary !== undefined || !isNaN(triageConfidence)) {
      await prisma.sastIssue.updateMany({
        where: {
          scopeId,
          fingerprint,
          lastSeenScanRunId: scanRunId,
        },
        data: {
          ...(llmSummary !== undefined ? { latestLlmSummary: llmSummary } : {}),
          ...(!isNaN(triageConfidence) ? { triageConfidence } : {}),
        },
      });
    }

    if (isNew) {
      inserted++;
    } else {
      updated++;
    }
  }

  return { inserted, updated };
}
