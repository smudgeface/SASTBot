import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  FindingsQuerySchema,
  IdParamsSchema,
  SastIssueListSchema,
  ScanFindingListSchema,
  ScanRunListSchema,
  ScanRunOutSchema,
  SbomComponentOutSchema,
} from "../schemas.js";
import { scanFindingToOut, scanRunToOut, sastIssueToOut, sbomComponentToOut } from "../services/mappers.js";
import { cancelScanRun, ScanRunNotFoundError } from "../services/scanService.js";

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
        summary: "List vulnerability findings for a scan run",
        params: IdParamsSchema,
        querystring: FindingsQuerySchema,
        response: {
          200: ScanFindingListSchema,
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

      const where: Record<string, unknown> = { scanRunId: req.params.id };
      if (req.query.severity) where.severity = req.query.severity;
      if (req.query.package) {
        where.component = {
          name: { contains: req.query.package, mode: "insensitive" },
        };
      }

      const findings = await prisma.scanFinding.findMany({
        where,
        include: {
          component: { select: { name: true, version: true, scope: true, isDevOnly: true, ecosystem: true } },
          // Pull the issue-level fields the audit view needs: LLM summary,
          // manifest path/line/snippet, reachability verdict. The scan
          // detail page renders the same expanded panel as the scope page
          // (sans triage/Jira) and reads everything off the joined issue.
          issue: {
            select: {
              latestLlmSummary: true,
              latestManifestFile: true,
              latestManifestLine: true,
              latestManifestSnippet: true,
              confirmedReachable: true,
              reachableConfidence: true,
              reachableReasoning: true,
              reachableCallSites: true,
              reachableModel: true,
              reachableAssessedAt: true,
            },
          },
        },
        orderBy: [
          { severity: "asc" }, // critical → high → low alphabetically; re-sort UI-side
          { cvssScore: "desc" },
        ],
      });

      return findings.map(scanFindingToOut);
    },
  );

  // Raw CycloneDX JSON download — returns the SBOM stored by the worker.
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

      const filename = `sbom-${(run.repo as { name: string }).name}-${params.id.slice(0, 8)}.cdx.json`;
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
        summary: "List SAST issues observed in this scan run",
        params: IdParamsSchema,
        response: {
          200: SastIssueListSchema,
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

      const issues = await prisma.sastIssue.findMany({
        where: { lastSeenScanRunId: req.params.id },
        orderBy: [{ latestSeverity: "asc" }, { latestStartLine: "asc" }],
      });

      return issues.map(sastIssueToOut);
    },
  );
};

export default scansRoutes;
