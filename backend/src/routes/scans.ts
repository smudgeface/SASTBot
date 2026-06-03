import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { createHash } from "node:crypto";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  FindingsQuerySchema,
  IdParamsSchema,
  PaginatedSchema,
  SastScanQuerySchema,
  ScanFindingOutSchema,
  ScanRunListQuerySchema,
  ScanRunOutSchema,
  SastIssueOutSchema,
  SbomComponentOutSchema,
} from "../schemas.js";
import { scanFindingToOut, scanRunToOut, sastIssueToOut, sbomComponentToOut } from "../services/mappers.js";
import {
  cancelScanRun,
  deleteScanRun,
  ScanIsCurrentLatestError,
  ScanRunNotFoundError,
  ScanStillRunningError,
} from "../services/scanService.js";
import { bySeverity, byStatus, cmpNum, cmpStr, dirSign } from "../services/issueSort.js";
import { sbomPathFor, sarifPathFor, tryReadArtifact } from "../services/artifactStore.js";

// Safety cap on list fetches that load rows into memory for sorting/serialization.
// Far above realistic per-scan/per-scope volumes (hundreds–low thousands); it's a
// backstop against pathological growth, not pagination. Hitting it is logged so a
// silent truncation can't masquerade as "complete". Proper DB-side pagination for
// these endpoints is tracked as a follow-up.
const LIST_SAFETY_CAP = 5000;

const scansRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/scans",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List scan runs visible to the current org (paginated)",
        querystring: ScanRunListQuerySchema,
        response: {
          200: PaginatedSchema(ScanRunOutSchema),
          401: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const { page, page_size } = req.query;
      const skip = (page - 1) * page_size;
      const where = { orgId: orgId ?? null };
      const [runs, total] = await Promise.all([
        prisma.scanRun.findMany({
          where,
          include: { scope: { select: { path: true } }, repo: { select: { name: true } } },
          orderBy: { createdAt: "desc" },
          skip,
          take: page_size,
        }),
        prisma.scanRun.count({ where }),
      ]);
      return { items: runs.map(scanRunToOut), total, page, page_size };
    },
  );

  typed.get(
    "/scans/:id",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "Get a scan run by id (includes SCA summary counters)",
        params: IdParamsSchema,
        response: {
          200: ScanRunOutSchema,
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const run = await prisma.scanRun.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        include: { scope: { select: { path: true } }, repo: { select: { name: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }
      // Resolve the triggering user for attribution (detail view only). No
      // ScanRun→User relation exists, so this is a separate one-row lookup;
      // null for api/schedule scans or a since-deleted user.
      const triggeredByUser = run.triggeredByUserId
        ? await prisma.user.findUnique({
            where: { id: run.triggeredByUserId },
            select: { email: true, name: true },
          })
        : null;
      return scanRunToOut({ ...run, triggeredByUser });
    },
  );

  typed.post(
    "/scans/:id/cancel",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["scans"],
        summary: "Cancel a pending or running scan run (admin-only). Idempotent on terminal runs.",
        params: IdParamsSchema,
        response: {
          200: ScanRunOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      try {
        const updated = await cancelScanRun(req.params.id, orgId);
        const withScope = await prisma.scanRun.findUnique({
          where: { id: updated.id },
          include: { scope: { select: { path: true } }, repo: { select: { name: true } } },
        });
        return scanRunToOut(withScope!);
      } catch (err) {
        if (err instanceof ScanRunNotFoundError) {
          return reply.code(404).send({ detail: "Scan run not found" });
        }
        throw err;
      }
    },
  );

  typed.delete(
    "/scans/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["scans"],
        summary: "Delete a scan run and its artifacts",
        description:
          "Refuses (409) when the run is the scope's current lastScanRunId; " +
          "refuses (400) when the run is still pending/running. Admin-only.",
        params: IdParamsSchema,
        response: {
          204: z.null(),
          400: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      try {
        await deleteScanRun(req.params.id, orgId);
        return reply.code(204).send();
      } catch (err) {
        if (err instanceof ScanRunNotFoundError) {
          return reply.code(404).send({ detail: "Scan run not found" });
        }
        if (err instanceof ScanStillRunningError) {
          return reply.code(400).send({
            detail: `Scan is still ${err.status}. Cancel it first via POST /scans/:id/cancel, then retry the delete.`,
          });
        }
        if (err instanceof ScanIsCurrentLatestError) {
          return reply.code(409).send({
            detail:
              `Cannot delete the scan currently anchoring this scope's truth set ` +
              `(it's scope.lastScanRunId=${err.scanRunId}). Trigger a new scan first, ` +
              `then delete this one.`,
          });
        }
        throw err;
      }
    },
  );

  typed.get(
    "/scans/:id/findings",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List vulnerability findings for a scan run (paginated)",
        params: IdParamsSchema,
        querystring: FindingsQuerySchema,
        response: {
          200: PaginatedSchema(ScanFindingOutSchema),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const run = await prisma.scanRun.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }

      const { page, page_size, severity, finding_type, dismissed_statuses, package: pkg, sort_by, sort_dir } = req.query;
      const where: Record<string, unknown> = { scanRunId: req.params.id };
      if (severity?.length) {
        where.severity = severity.length === 1 ? severity[0] : { in: severity };
      }
      if (finding_type?.length) {
        where.findingType = finding_type.length === 1 ? finding_type[0] : { in: finding_type };
      }
      if (pkg) {
        where.component = {
          name: { contains: pkg, mode: "insensitive" },
        };
      }
      // dismissed_statuses filters against the joined SCA issue's triage
      // state — the scan-page view shares triage with the scope page so
      // the "Fixed" / "Won't fix" filters mean the same thing on both.
      if (dismissed_statuses?.length) {
        where.issue = {
          dismissedStatus: dismissed_statuses.length === 1 ? dismissed_statuses[0] : { in: dismissed_statuses },
        };
      }

      // Bounded per-scan dataset — fetch all matching rows then post-sort
      // + slice. Mirrors the scope-page SCA route (issueSort.ts helpers
      // give the same severity / status CASE ordering).
      const [all, total] = await Promise.all([
        prisma.scanFinding.findMany({
          where,
          include: {
            component: { select: { name: true, version: true, scope: true, isDevOnly: true, ecosystem: true } },
            issue: {
              select: {
                latestLlmSummary: true,
                latestManifestFile: true,
                latestManifestLine: true,
                latestManifestSnippet: true,
                dismissedStatus: true,
                confirmedReachable: true,
                reachableConfidence: true,
                reachableReasoning: true,
                reachableCallSites: true,
                reachableModel: true,
                reachableAssessedAt: true,
              },
            },
          },
        }),
        prisma.scanFinding.count({ where }),
      ]);

      const sign = dirSign(sort_dir);
      all.sort((a, b) => {
        let primary = 0;
        switch (sort_by) {
          case "severity":
            primary = bySeverity(a.severity, b.severity) ||
                      cmpNum(b.cvssScore, a.cvssScore);
            break;
          case "summary":
            primary = cmpStr(a.issue?.latestLlmSummary ?? a.summary, b.issue?.latestLlmSummary ?? b.summary);
            break;
          case "location":
            primary = cmpStr(a.issue?.latestManifestFile ?? null, b.issue?.latestManifestFile ?? null) ||
                      cmpNum(a.issue?.latestManifestLine ?? null, b.issue?.latestManifestLine ?? null);
            break;
          case "status":
            primary = byStatus(a.issue?.dismissedStatus ?? "pending", b.issue?.dismissedStatus ?? "pending");
            break;
          case "last_seen":
            primary = a.createdAt.getTime() - b.createdAt.getTime();
            break;
          default:
            primary = bySeverity(a.severity, b.severity) ||
                      cmpNum(b.cvssScore, a.cvssScore);
        }
        if (primary !== 0) return sort_by ? primary * sign : primary;
        return a.id.localeCompare(b.id);
      });

      const skip = (page - 1) * page_size;
      const items = all.slice(skip, skip + page_size);
      return { items: items.map(scanFindingToOut), total, page, page_size };
    },
  );

  // Post-augmentation canonical CycloneDX 1.7 SBOM for this scan run, served
  // from the artifact file at ${ARTIFACT_DIR}/sbom/${scanRunId}.json. Written
  // by the worker's sbom_emit phase using stableStringify so two reads of an
  // unchanged scan return byte-identical output (ETag stable).
  //
  // Legacy scans (run before M9 Stream B) have no artifact file and return 404
  // with a re-run-the-scan hint. The user-facing UI should render this as a
  // friendly "no SBOM for this old scan" message.
  //
  // This is the scan-level (per-run) artifact. For the scope-level view that
  // reflects operator edits to scope_components, use
  // GET /api/scopes/:id/sbom-json.
  app.get(
    "/scans/:id/sbom",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "Download the curated CycloneDX 1.7 SBOM for a scan run",
        description:
          "Returns the post-augmentation curated CycloneDX 1.7 JSON for this " +
          "specific scan run as a file download (ETag-cached). 404 if the scan " +
          "has no artifact file (still running, legacy pre-M9 scan, or an " +
          "sbom_emit failure). For the operator-edited scope-level SBOM, use " +
          "GET /api/scopes/:id/sbom-json.",
        params: IdParamsSchema,
        // No 200 body schema on purpose: the response is a raw JSON file stream,
        // not a Zod-validated object.
        response: { 401: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = (req as unknown as { user?: { orgId?: string } }).user?.orgId ?? null;
      const params = req.params as { id: string };

      const run = await prisma.scanRun.findFirst({
        where: { id: params.id, orgId: orgId ?? null },
        select: { id: true, repo: { select: { name: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }

      const body = await tryReadArtifact(sbomPathFor(run.id));
      if (!body) {
        return reply.code(404).send({
          detail:
            `SBOM artifact not available for this scan. This is expected if: ` +
            `(a) the scan is still running, ` +
            `(b) the scan completed before the artifact-file pipeline shipped (M9 Stream B), ` +
            `(c) the worker recorded an sbom_emit_failed warning during this scan. ` +
            `To produce a downloadable SBOM, re-trigger the scan from the repo page.`,
        });
      }

      const pretty = body.toString("utf8");
      const etag = `"${createHash("sha256").update(pretty).digest("hex").slice(0, 32)}"`;
      const ifNoneMatch = (req.headers as Record<string, string | undefined>)["if-none-match"];
      if (ifNoneMatch === etag) {
        return reply.code(304).send();
      }
      const filename = `sbom-${(run.repo as { name: string }).name}-${params.id.slice(0, 8)}.cdx.json`;
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="${filename}"`)
        .header("ETag", etag)
        .send(pretty);
    },
  );

  // SARIF v2.1.0 export of the LLM SAST findings observed in this run.
  // Served from the artifact file at ${ARTIFACT_DIR}/sarif/${scanRunId}.sarif.json.
  // Written by the worker's sarif_emit phase. Legacy scans (run before M9 Stream B)
  // have no artifact file and return 404 with a re-run hint.
  app.get(
    "/scans/:id/sast-sarif",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "Download the SARIF v2.1.0 SAST report for a scan run",
        description:
          "Returns the SARIF v2.1.0 document of the LLM SAST findings for this " +
          "scan run as a file download (ETag-cached). 404 if the scan has no " +
          "artifact file (still running, legacy pre-M9 scan, or a sarif_emit " +
          "failure) — re-trigger the scan to produce one.",
        params: IdParamsSchema,
        // No 200 body schema on purpose: the response is a raw JSON file stream.
        response: { 401: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = (req as unknown as { user?: { orgId?: string } }).user?.orgId ?? null;
      const params = req.params as { id: string };

      const run = await prisma.scanRun.findFirst({
        where: { id: params.id, orgId: orgId ?? null },
        select: { id: true, repo: { select: { name: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }

      const body = await tryReadArtifact(sarifPathFor(run.id));
      if (!body) {
        return reply.code(404).send({
          detail:
            `SARIF artifact not available for this scan. This is expected if: ` +
            `(a) the scan is still running, ` +
            `(b) the scan completed before the artifact-file pipeline shipped (M9 Stream B), ` +
            `(c) the worker recorded a sarif_emit_failed warning during this scan. ` +
            `To produce a downloadable SARIF, re-trigger the scan from the repo page.`,
        });
      }

      const pretty = body.toString("utf8");
      const etag = `"${createHash("sha256").update(pretty).digest("hex").slice(0, 32)}"`;
      const ifNoneMatch = (req.headers as Record<string, string | undefined>)["if-none-match"];
      if (ifNoneMatch === etag) {
        return reply.code(304).send();
      }
      const filename = `sast-${(run.repo as { name: string }).name}-${params.id.slice(0, 8)}.sarif.json`;
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="${filename}"`)
        .header("ETag", etag)
        .send(pretty);
    },
  );

  // Trigger a scan — kept here to minimise route file count.
  // (Previously lived in adminRepos.ts but it's really a scan operation.)
  // M6q: now returns occurrences[], manifest_file, discovery_method (per plan §2).
  // No linked_issue_ids — that's a scope-level concept only.
  typed.get(
    "/scans/:id/components",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List SBOM components for a scan run",
        params: IdParamsSchema,
        response: {
          200: z.array(SbomComponentOutSchema),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const run = await prisma.scanRun.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true },
      });
      if (!run) return reply.code(404).send({ detail: "Scan run not found" });

      const comps = await prisma.sbomComponent.findMany({
        where: { scanRunId: req.params.id },
        orderBy: { name: "asc" },
        take: LIST_SAFETY_CAP,
      });
      if (comps.length === LIST_SAFETY_CAP) {
        req.log.warn({ scanRunId: req.params.id, cap: LIST_SAFETY_CAP }, "[scans] sbom-components list hit safety cap — result truncated");
      }
      return comps.map(sbomComponentToOut);
    },
  );
  // ── SAST findings ──────────────────────────────────────────────────────────

  // Returns the SAST issues observed in this scan run — i.e. issues whose
  // `lastSeenScanRunId` matches. The legacy per-scan `sast_findings` table
  // is no longer written (M6g LLM SAST cutover); the deduplicated issue is
  // the unit of truth and what the badge counter reflects.
  typed.get(
    "/scans/:id/sast-findings",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List SAST issues observed in this scan run (paginated)",
        params: IdParamsSchema,
        querystring: SastScanQuerySchema,
        response: {
          200: PaginatedSchema(SastIssueOutSchema),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const run = await prisma.scanRun.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true },
      });
      if (!run) return reply.code(404).send({ detail: "Scan run not found" });

      const { page, page_size, severity, triage_status, sort_by, sort_dir } = req.query;
      const where: Record<string, unknown> = { lastSeenScanRunId: req.params.id };
      if (severity?.length) {
        where.latestSeverity = severity.length === 1 ? severity[0] : { in: severity };
      }
      if (triage_status?.length) {
        where.triageStatus = triage_status.length === 1 ? triage_status[0] : { in: triage_status };
      }

      const [all, total] = await Promise.all([
        prisma.sastIssue.findMany({ where, take: LIST_SAFETY_CAP }),
        prisma.sastIssue.count({ where }),
      ]);
      if (all.length === LIST_SAFETY_CAP) {
        req.log.warn({ scanRunId: req.params.id, cap: LIST_SAFETY_CAP }, "[scans] sast-findings list hit safety cap — sort/page over truncated set");
      }

      const sign = dirSign(sort_dir);
      all.sort((a, b) => {
        let primary = 0;
        switch (sort_by) {
          case "severity":
            primary = bySeverity(a.latestSeverity, b.latestSeverity);
            break;
          case "summary":
            primary = cmpStr(a.latestLlmSummary ?? a.latestRuleMessage, b.latestLlmSummary ?? b.latestRuleMessage);
            break;
          case "location":
            primary = cmpStr(a.latestFilePath, b.latestFilePath) ||
                      cmpNum(a.latestStartLine, b.latestStartLine);
            break;
          case "status":
            primary = byStatus(a.triageStatus, b.triageStatus);
            break;
          case "last_seen":
            primary = a.lastSeenAt.getTime() - b.lastSeenAt.getTime();
            break;
          default:
            primary = bySeverity(a.latestSeverity, b.latestSeverity) ||
                      cmpNum(a.latestStartLine, b.latestStartLine);
        }
        if (primary !== 0) return sort_by ? primary * sign : primary;
        return a.id.localeCompare(b.id);
      });

      const skip = (page - 1) * page_size;
      const items = all.slice(skip, skip + page_size);
      return { items: items.map(sastIssueToOut), total, page, page_size };
    },
  );
};

export default scansRoutes;
