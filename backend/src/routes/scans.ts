import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  FindingsQuerySchema,
  IdParamsSchema,
  PaginatedSchema,
  SastScanQuerySchema,
  ScanFindingOutSchema,
  ScanRunListSchema,
  ScanRunOutSchema,
  SastIssueOutSchema,
  SbomComponentOutSchema,
} from "../schemas.js";
import { scanFindingToOut, scanRunToOut, sastIssueToOut, sbomComponentToOut } from "../services/mappers.js";
import { cancelScanRun, ScanRunNotFoundError } from "../services/scanService.js";
import { bySeverity, byStatus, cmpNum, cmpStr, dirSign } from "../services/issueSort.js";

const scansRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/scans",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List scan runs visible to the current org",
        response: {
          200: ScanRunListSchema,
          401: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const runs = await prisma.scanRun.findMany({
        where: { orgId: orgId ?? null },
        include: { scope: { select: { path: true } } },
        orderBy: { createdAt: "desc" },
      });
      return runs.map(scanRunToOut);
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
        include: { scope: { select: { path: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }
      return scanRunToOut(run);
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
          include: { scope: { select: { path: true } } },
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

  // Raw cdxgen output for this scan. The scan page is the audit-trail
  // surface — it shows what cdxgen actually produced before Stage-1
  // cleanup and Stage-2 LLM augmentation. Operators looking for the
  // curated, ship-this-to-the-customer SBOM use the scope-level endpoint
  // (/api/scopes/:id/sbom-json) instead. (M6q review #15.)
  app.get(
    "/scans/:id/sbom",
    {
      preHandler: [app.authenticate],
    },
    async (req, reply) => {
      const orgId = (req as unknown as { user?: { orgId?: string } }).user?.orgId ?? null;
      const params = req.params as { id: string };

      const run = await prisma.scanRun.findFirst({
        where: { id: params.id, orgId: orgId ?? null },
        select: { id: true, sbomJson: true, repo: { select: { name: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }
      if (!run.sbomJson) {
        return reply.code(404).send({ detail: "SBOM not yet available for this scan" });
      }

      const filename = `sbom-raw-${(run.repo as { name: string }).name}-${params.id.slice(0, 8)}.cdx.json`;
      const pretty = JSON.stringify(run.sbomJson, null, 2);
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="${filename}"`)
        .send(pretty);
    },
  );

  // SARIF v2.1.0 export of the LLM SAST findings observed in this run.
  // Mirrors the SBOM endpoint: pretty-printed JSON with an attachment
  // disposition so browsers offer "save as" by default. Operators can
  // hand the file off to dashboards / CI gates / compliance evidence.
  app.get(
    "/scans/:id/sast-sarif",
    {
      preHandler: [app.authenticate],
    },
    async (req, reply) => {
      const orgId = (req as unknown as { user?: { orgId?: string } }).user?.orgId ?? null;
      const params = req.params as { id: string };

      const run = await prisma.scanRun.findFirst({
        where: { id: params.id, orgId: orgId ?? null },
        select: { id: true, sastSarif: true, repo: { select: { name: true } } },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }
      if (!run.sastSarif) {
        return reply
          .code(404)
          .send({ detail: "SARIF not yet available for this scan" });
      }

      const filename = `sast-${(run.repo as { name: string }).name}-${params.id.slice(0, 8)}.sarif.json`;
      const pretty = JSON.stringify(run.sastSarif, null, 2);
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="${filename}"`)
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
      });
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
        prisma.sastIssue.findMany({ where }),
        prisma.sastIssue.count({ where }),
      ]);

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
