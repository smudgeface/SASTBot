/**
 * sbomIngest.ts — B2 phase service.
 *
 * For `source='cdxgen'` scans: caller skips this (sbom_components is already
 * populated by persistAugmentedComponents). This module is reserved for the
 * future external-upload flow (B7 in docs/M9_STREAM_B_PLAN.md §11) where the
 * canonical SBOM file is the *input* and sbom_components is the *output*.
 *
 * The function below is a skeleton — full extraction of CycloneDX components
 * into sbom_components rows is deferred to whoever ships the upload route.
 */

import { sbomPathFor, tryReadArtifact } from "./artifactStore.js";

export async function ingestSbomFromArtifact(scanRunId: string): Promise<void> {
  const body = await tryReadArtifact(sbomPathFor(scanRunId));
  if (!body) {
    throw new Error(`sbom_ingest: no SBOM artifact found for scan ${scanRunId}`);
  }
  // TODO(M9 B7): parse CycloneDX 1.7 doc, clear sbom_components for this
  // scanRunId, insert rows from doc.components. The M7 (scan_run_id, purl)
  // unique index makes re-runs idempotent.
  //
  // Skeleton intentionally throws so callers know ingestion is not yet wired
  // for the upload path. The cdxgen flow short-circuits this function in
  // worker.ts before calling it.
  throw new Error(
    "sbom_ingest: external-upload flow not yet implemented (B7). " +
    "For source='cdxgen' scans, sbom_components is already populated; " +
    "this function should not have been called.",
  );
}
