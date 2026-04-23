import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  FindingsQuerySchema,
  IdParamsSchema,
  SastFindingListSchema,
  SastFindingParamsSchema,
  SastFindingOutSchema,
  SastFindingsQuerySchema,
  SastTriageBodySchema,
  ScanFindingListSchema,
  ScanRunListSchema,
  ScanRunOutSchema,
} from "../schemas.js";
import { scanFindingToOut, scanRunToOut, sastFindingToOut } from "../services/mappers.js";

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
        include: { component: { select: { name: true, version: true, scope: true } } },
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

  // Trigger a scan — kept here to minimise route file count.
  // (Previously lived in adminRepos.ts but it's really a scan operation.)
  typed.get(
    "/scans/:id/components",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List SBOM components for a scan run",
        params: IdParamsSchema,
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              name: z.string(),
              version: z.string().nullable(),
              purl: z.string(),
              ecosystem: z.string().nullable(),
              licenses: z.array(z.string()),
              component_type: z.string(),
            }),
          ),
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
      return comps.map((c) => ({
        id: c.id,
        name: c.name,
        version: c.version,
        purl: c.purl,
        ecosystem: c.ecosystem,
        licenses: c.licenses,
        component_type: c.componentType,
        scope: c.scope,
      }));
    },
  );
  // ── SAST findings ──────────────────────────────────────────────────────────

  typed.get(
    "/scans/:id/sast-findings",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List SAST findings for a scan run",
        params: IdParamsSchema,
        querystring: SastFindingsQuerySchema,
        response: {
          200: SastFindingListSchema,
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

      const where: Record<string, unknown> = { scanRunId: req.params.id };
      if (req.query.severity) where.severity = req.query.severity;
      if (req.query.file_path) {
        where.filePath = { startsWith: req.query.file_path };
      }

      const findings = await prisma.sastFinding.findMany({
        where,
        orderBy: [{ severity: "asc" }, { startLine: "asc" }],
      });

      return findings.map(sastFindingToOut);
    },
  );

  typed.post(
    "/scans/:id/sast-findings/:fid/triage",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["scans"],
        summary: "Update triage status for a SAST finding (admin-only)",
        params: SastFindingParamsSchema,
        body: SastTriageBodySchema,
        response: {
          200: SastFindingOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
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

      const finding = await prisma.sastFinding.findFirst({
        where: { id: req.params.fid, scanRunId: req.params.id },
      });
      if (!finding) return reply.code(404).send({ detail: "SAST finding not found" });

      // Deprecated: forward to the issue. Triage state lives on SastIssue now.
      const { status, reason } = req.body;
      await prisma.sastIssue.update({
        where: { id: finding.issueId },
        data: {
          triageStatus: status,
          suppressedReason: status === "pending" ? null : (reason ?? null),
          suppressedAt: status === "suppressed" ? new Date() : null,
          suppressedByUserId: status === "suppressed" ? (req.user?.id ?? null) : null,
          triageConfidence: status === "pending" ? null : undefined,
          triageReasoning: status === "pending" ? null : undefined,
        },
      });

      return sastFindingToOut(finding);
    },
  );
};

export default scansRoutes;
