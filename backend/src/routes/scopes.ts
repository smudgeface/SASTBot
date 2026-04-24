import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  IdParamsSchema,
  JiraTicketOutSchema,
  LinkJiraTicketBodySchema,
  PaginatedSchema,
  PaginationQuerySchema,
  SastIssueListSchema,
  SastIssueOutSchema,
  SastIssueTriageBodySchema,
  SastSeveritySchema,
  SastTriageStatusSchema,
  ScaIssueDismissBodySchema,
  ScaIssueListSchema,
  ScaIssueOutSchema,
  SeveritySchema,
  FindingTypeSchema,
} from "../schemas.js";
import { jiraTicketToOut, sastIssueToOut, scaIssueToOut, scanRunToOut, sbomComponentToOut } from "../services/mappers.js";
import { linkSastIssueToTicket, linkScaIssueToTicket, refreshTicket, unlinkSastIssue, unlinkScaIssue } from "../services/jiraTicketService.js";

// ---------------------------------------------------------------------------
// Scope list / detail schemas
// ---------------------------------------------------------------------------

const ScopeListItemSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid().nullable(),
  repo_id: z.string().uuid(),
  repo_name: z.string(),
  repo_branch: z.string(),
  path: z.string(),
  display_name: z.string().nullable(),
  is_active: z.boolean(),
  last_scan_run_id: z.string().uuid().nullable(),
  last_scan_completed_at: z.string().nullable(),
  active_sast_issue_count: z.number().int().nonnegative(),
  active_sca_issue_count: z.number().int().nonnegative(),
  critical_count: z.number().int().nonnegative(),
  high_count: z.number().int().nonnegative(),
  medium_count: z.number().int().nonnegative(),
  low_count: z.number().int().nonnegative(),
  pending_triage_count: z.number().int().nonnegative(),
  created_at: z.string(),
});

const ScopeDetailSchema = ScopeListItemSchema.extend({
  resolved_sast_count: z.number().int().nonnegative(),
  resolved_sca_count: z.number().int().nonnegative(),
});

// Coerce a repeated query param (string | string[] | undefined) to string[] | undefined
function toArray<T extends string>(
  schema: z.ZodType<T>,
): z.ZodType<T[] | undefined> {
  return z
    .preprocess(
      (v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v]),
      z.array(schema).optional(),
    ) as z.ZodType<T[] | undefined>;
}

// Query schemas for issue lists
const SastIssuesQuerySchema = PaginationQuerySchema.extend({
  severity: toArray(SastSeveritySchema),
  triage_status: toArray(SastTriageStatusSchema),
  has_jira_ticket: z.enum(["yes", "no"]).optional(),
  seen_since_last_scan: z.enum(["new", "unchanged", "resolved"]).optional(),
  include_resolved: z.coerce.boolean().default(false),
});

const ScaIssuesQuerySchema = PaginationQuerySchema.extend({
  severity: toArray(SeveritySchema),
  finding_type: toArray(FindingTypeSchema),
  dismissed_status: z.enum(["active", "confirmed", "acknowledged", "wont_fix", "false_positive"]).optional(),
  has_jira_ticket: z.enum(["yes", "no"]).optional(),
  reachable: z.coerce.boolean().optional(),
  has_fix: z.coerce.boolean().optional(),
  hide_dev: z.coerce.boolean().optional(),
  seen_since_last_scan: z.enum(["new", "unchanged", "resolved"]).optional(),
  include_resolved: z.coerce.boolean().default(false),
});

// Prisma sorts severity strings alphabetically (low < medium), so we post-sort.
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, unknown: 4, info: 5,
};
function bySeverity(a: string, b: string): number {
  return (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9);
}

const scopesRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  // ---------------------------------------------------------------------------
  // GET /scopes — list all scopes with aggregated issue counts
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "List scan scopes with issue summary counts",
        querystring: z.object({
          repo_id: z.string().uuid().optional(),
          include_inactive: z.coerce.boolean().default(false),
        }),
        response: {
          200: z.array(ScopeListItemSchema),
          401: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const { repo_id, include_inactive } = req.query;

      const scopes = await prisma.scanScope.findMany({
        where: {
          orgId: orgId ?? null,
          ...(repo_id ? { repoId: repo_id } : {}),
          ...(include_inactive ? {} : { isActive: true }),
        },
        include: { repo: { select: { name: true, defaultBranch: true } } },
        orderBy: [{ repo: { name: "asc" } }, { path: "asc" }],
      });

      return Promise.all(scopes.map(async (scope) => {
        const repo = scope.repo as { name: string; defaultBranch: string };

        const activeWhere = (sev: string) => ({
          scopeId: scope.id, dismissedStatus: "active", latestSeverity: sev,
        });
        const activeSastWhere = (sev: string) => ({
          scopeId: scope.id, latestSeverity: sev,
          triageStatus: { notIn: ["suppressed", "false_positive", "fixed"] as string[] },
        });
        const combined = async (sev: string) => {
          const [sca, sast] = await Promise.all([
            prisma.scaIssue.count({ where: activeWhere(sev) }),
            prisma.sastIssue.count({ where: activeSastWhere(sev) }),
          ]);
          return sca + sast;
        };

        const [
          activeSastCount,
          activeSCACount,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          pendingTriageCount,
        ] = await Promise.all([
          prisma.sastIssue.count({
            where: { scopeId: scope.id, triageStatus: { notIn: ["suppressed", "false_positive", "fixed"] } },
          }),
          prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: "active" } }),
          combined("critical"),
          combined("high"),
          combined("medium"),
          combined("low"),
          prisma.sastIssue.count({ where: { scopeId: scope.id, triageStatus: "pending" } }),
        ]);

        return {
          id: scope.id,
          org_id: scope.orgId,
          repo_id: scope.repoId,
          repo_name: repo.name,
          repo_branch: repo.defaultBranch,
          path: scope.path,
          display_name: scope.displayName,
          is_active: scope.isActive,
          last_scan_run_id: scope.lastScanRunId,
          last_scan_completed_at: scope.lastScanCompletedAt?.toISOString() ?? null,
          active_sast_issue_count: activeSastCount,
          active_sca_issue_count: activeSCACount,
          critical_count: criticalCount,
          high_count: highCount,
          medium_count: mediumCount,
          low_count: lowCount,
          pending_triage_count: pendingTriageCount,
          created_at: scope.createdAt.toISOString(),
        };
      }));
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id — scope detail
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "Get a scan scope by id with full counts",
        params: IdParamsSchema,
        response: {
          200: ScopeDetailSchema,
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        include: { repo: { select: { name: true, defaultBranch: true } } },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      const repo = scope.repo as { name: string; defaultBranch: string };
      const lastScanRunId = scope.lastScanRunId;

      const activeWhereD = (sev: string) => ({
        scopeId: scope.id, dismissedStatus: "active", latestSeverity: sev,
      });
      const activeSastWhereD = (sev: string) => ({
        scopeId: scope.id, latestSeverity: sev,
        triageStatus: { notIn: ["suppressed", "false_positive", "fixed"] as string[] },
      });
      const combinedD = async (sev: string) => {
        const [sca, sast] = await Promise.all([
          prisma.scaIssue.count({ where: activeWhereD(sev) }),
          prisma.sastIssue.count({ where: activeSastWhereD(sev) }),
        ]);
        return sca + sast;
      };

      const [
        activeSastCount,
        activeSCACount,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        pendingTriageCount,
        resolvedSastCount,
        resolvedScaCount,
      ] = await Promise.all([
        prisma.sastIssue.count({
          where: { scopeId: scope.id, triageStatus: { notIn: ["suppressed", "false_positive", "fixed"] } },
        }),
        prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: "active" } }),
        combinedD("critical"),
        combinedD("high"),
        combinedD("medium"),
        combinedD("low"),
        prisma.sastIssue.count({ where: { scopeId: scope.id, triageStatus: "pending" } }),
        lastScanRunId
          ? prisma.sastIssue.count({ where: { scopeId: scope.id, lastSeenScanRunId: { not: lastScanRunId } } })
          : 0,
        lastScanRunId
          ? prisma.scaIssue.count({ where: { scopeId: scope.id, lastSeenScanRunId: { not: lastScanRunId } } })
          : 0,
      ]);

      return {
        id: scope.id,
        org_id: scope.orgId,
        repo_id: scope.repoId,
        repo_name: repo.name,
        repo_branch: repo.defaultBranch,
        path: scope.path,
        display_name: scope.displayName,
        is_active: scope.isActive,
        last_scan_run_id: scope.lastScanRunId,
        last_scan_completed_at: scope.lastScanCompletedAt?.toISOString() ?? null,
        active_sast_issue_count: activeSastCount,
        active_sca_issue_count: activeSCACount,
        critical_count: criticalCount,
        high_count: highCount,
        medium_count: mediumCount,
        low_count: lowCount,
        pending_triage_count: pendingTriageCount,
        resolved_sast_count: resolvedSastCount,
        resolved_sca_count: resolvedScaCount,
        created_at: scope.createdAt.toISOString(),
      };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/sast-issues
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id/sast-issues",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "List SAST issues for a scope (paginated)",
        params: IdParamsSchema,
        querystring: SastIssuesQuerySchema,
        response: {
          200: PaginatedSchema(SastIssueOutSchema),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true, lastScanRunId: true, lastScanCompletedAt: true },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      const { page, page_size, severity, triage_status, has_jira_ticket, seen_since_last_scan, include_resolved } = req.query;
      const lastScanRunId = scope.lastScanRunId;

      const where: Record<string, unknown> = { scopeId: req.params.id };
      if (severity?.length)      where.latestSeverity = severity.length === 1 ? severity[0] : { in: severity };
      if (triage_status?.length) where.triageStatus   = triage_status.length === 1 ? triage_status[0] : { in: triage_status };
      if (has_jira_ticket === "yes") where.jiraTicketId = { not: null };
      if (has_jira_ticket === "no") where.jiraTicketId = null;

      // Lifecycle filters — compare lastSeenScanRunId to avoid timestamp ordering issues
      if (seen_since_last_scan && lastScanRunId) {
        if (seen_since_last_scan === "new") {
          where.firstSeenScanRunId = lastScanRunId;
        } else if (seen_since_last_scan === "resolved") {
          where.lastSeenScanRunId = { not: lastScanRunId };
        } else if (seen_since_last_scan === "unchanged") {
          where.lastSeenScanRunId = lastScanRunId;
          where.firstSeenScanRunId = { not: lastScanRunId };
        }
      }

      // By default hide issues not seen in the latest scan
      if (!include_resolved && lastScanRunId && !seen_since_last_scan) {
        where.lastSeenScanRunId = lastScanRunId;
      }

      const skip = (page - 1) * page_size;
      const [all, total] = await Promise.all([
        prisma.sastIssue.findMany({ where }),
        prisma.sastIssue.count({ where }),
      ]);
      all.sort((a, b) =>
        bySeverity(a.latestSeverity, b.latestSeverity) ||
        b.lastSeenAt.getTime() - a.lastSeenAt.getTime() ||
        a.id.localeCompare(b.id),
      );
      const items = all.slice(skip, skip + page_size);

      return { items: items.map(sastIssueToOut), total, page, page_size };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/sca-issues
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id/sca-issues",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "List SCA issues for a scope (paginated)",
        params: IdParamsSchema,
        querystring: ScaIssuesQuerySchema,
        response: {
          200: PaginatedSchema(ScaIssueOutSchema),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true, lastScanRunId: true, lastScanCompletedAt: true },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      const {
        page, page_size, severity, finding_type, dismissed_status,
        has_jira_ticket, reachable, has_fix, hide_dev,
        seen_since_last_scan, include_resolved,
      } = req.query;
      const lastScanRunId = scope.lastScanRunId;

      const where: Record<string, unknown> = { scopeId: req.params.id };
      if (severity?.length)      where.latestSeverity     = severity.length === 1     ? severity[0]      : { in: severity };
      if (finding_type?.length)  where.latestFindingType  = finding_type.length === 1 ? finding_type[0]  : { in: finding_type };
      if (dismissed_status) where.dismissedStatus = dismissed_status;
      if (has_jira_ticket === "yes") where.jiraTicketId = { not: null };
      if (has_jira_ticket === "no") where.jiraTicketId = null;
      if (reachable === true) where.confirmedReachable = true;
      if (has_fix === true) where.latestHasFix = true;
      if (hide_dev === true) where.latestComponentScope = { not: "optional" };

      if (seen_since_last_scan && lastScanRunId) {
        if (seen_since_last_scan === "new") {
          where.firstSeenScanRunId = lastScanRunId;
        } else if (seen_since_last_scan === "resolved") {
          where.lastSeenScanRunId = { not: lastScanRunId };
        } else if (seen_since_last_scan === "unchanged") {
          where.lastSeenScanRunId = lastScanRunId;
          where.firstSeenScanRunId = { not: lastScanRunId };
        }
      }

      if (!include_resolved && lastScanRunId && !seen_since_last_scan) {
        where.lastSeenScanRunId = lastScanRunId;
      }

      const skip = (page - 1) * page_size;
      const [all, total] = await Promise.all([
        prisma.scaIssue.findMany({ where }),
        prisma.scaIssue.count({ where }),
      ]);
      all.sort((a, b) =>
        bySeverity(a.latestSeverity, b.latestSeverity) ||
        (b.latestCvssScore ?? 0) - (a.latestCvssScore ?? 0) ||
        a.id.localeCompare(b.id),
      );
      const items = all.slice(skip, skip + page_size);

      return { items: items.map(scaIssueToOut), total, page, page_size };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/components — from the most recent scan run
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id/components",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "List SBOM components for the most recent scan of this scope",
        params: IdParamsSchema,
        querystring: PaginationQuerySchema.extend({
          has_findings: z.coerce.boolean().optional(),
        }),
        response: {
          200: PaginatedSchema(z.object({
            id: z.string(),
            scan_run_id: z.string(),
            name: z.string(),
            version: z.string().nullable(),
            purl: z.string(),
            ecosystem: z.string().nullable(),
            licenses: z.array(z.string()),
            component_type: z.string(),
            scope: z.string().nullable(),
          })),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true, lastScanRunId: true },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });
      if (!scope.lastScanRunId) return { items: [], total: 0, page: req.query.page, page_size: req.query.page_size };

      const { page, page_size, has_findings } = req.query;
      const where: Record<string, unknown> = { scanRunId: scope.lastScanRunId };
      if (has_findings === true) {
        where.findings = { some: {} };
      }

      const skip = (page - 1) * page_size;
      const [comps, total] = await Promise.all([
        prisma.sbomComponent.findMany({
          where,
          orderBy: { name: "asc" },
          skip,
          take: page_size,
        }),
        prisma.sbomComponent.count({ where }),
      ]);

      return { items: comps.map(sbomComponentToOut), total, page, page_size };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/scans — recent scan runs (for the "recent scans" drawer)
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id/scans",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes"],
        summary: "List recent scan runs for a scope",
        params: IdParamsSchema,
        querystring: z.object({
          limit: z.coerce.number().int().min(1).max(100).default(20),
        }),
        response: {
          200: z.array(z.object({
            id: z.string().uuid(),
            status: z.string(),
            triggered_by: z.string(),
            started_at: z.string().nullable(),
            finished_at: z.string().nullable(),
            error: z.string().nullable(),
            component_count: z.number().int(),
            critical_count: z.number().int(),
            high_count: z.number().int(),
            sast_finding_count: z.number().int(),
            created_at: z.string(),
          })),
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      const runs = await prisma.scanRun.findMany({
        where: { scopeId: req.params.id },
        orderBy: { createdAt: "desc" },
        take: req.query.limit,
        select: {
          id: true, status: true, triggeredBy: true,
          startedAt: true, finishedAt: true, error: true,
          componentCount: true, criticalCount: true, highCount: true,
          sastFindingCount: true, createdAt: true,
        },
      });

      return runs.map((r) => ({
        id: r.id,
        status: r.status,
        triggered_by: r.triggeredBy,
        started_at: r.startedAt?.toISOString() ?? null,
        finished_at: r.finishedAt?.toISOString() ?? null,
        error: r.error,
        component_count: r.componentCount,
        critical_count: r.criticalCount,
        high_count: r.highCount,
        sast_finding_count: r.sastFindingCount,
        created_at: r.createdAt.toISOString(),
      }));
    },
  );

  // ---------------------------------------------------------------------------
  // POST /sast-issues/:id/triage
  // ---------------------------------------------------------------------------

  typed.post(
    "/api/sast-issues/:id/triage",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Triage a SAST issue (admin-only)",
        params: IdParamsSchema,
        body: SastIssueTriageBodySchema,
        response: {
          200: SastIssueOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.sastIssue.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
      });
      if (!issue) return reply.code(404).send({ detail: "SAST issue not found" });

      const { status, reason } = req.body;
      const updated = await prisma.sastIssue.update({
        where: { id: req.params.id },
        data: {
          triageStatus: status,
          suppressedReason: status === "pending" ? null : (reason ?? null),
          suppressedAt: status === "suppressed" ? new Date() : null,
          suppressedByUserId: status === "suppressed" ? (req.user?.id ?? null) : null,
          triageConfidence: status === "pending" ? null : undefined,
          triageReasoning: status === "pending" ? null : undefined,
        },
      });

      return sastIssueToOut(updated);
    },
  );

  // ---------------------------------------------------------------------------
  // POST /sca-issues/:id/dismiss
  // ---------------------------------------------------------------------------

  typed.post(
    "/api/sca-issues/:id/dismiss",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Dismiss a SCA issue (admin-only)",
        params: IdParamsSchema,
        body: ScaIssueDismissBodySchema,
        response: {
          200: ScaIssueOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.scaIssue.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
      });
      if (!issue) return reply.code(404).send({ detail: "SCA issue not found" });

      const { status, reason } = req.body;
      const updated = await prisma.scaIssue.update({
        where: { id: req.params.id },
        data: {
          dismissedStatus: status,
          dismissedReason: status === "active" ? null : (reason ?? null),
          dismissedAt: status === "active" ? null : new Date(),
          dismissedByUserId: status === "active" ? null : (req.user?.id ?? null),
        },
      });

      return scaIssueToOut(updated);
    },
  );

  // ---------------------------------------------------------------------------
  // PUT /sast-issues/:id/notes
  // ---------------------------------------------------------------------------

  typed.put(
    "/api/sast-issues/:id/notes",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["issues"],
        summary: "Set notes on a SAST issue",
        params: IdParamsSchema,
        body: z.object({ notes: z.string() }),
        response: {
          200: SastIssueOutSchema,
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.sastIssue.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
      });
      if (!issue) return reply.code(404).send({ detail: "SAST issue not found" });

      const updated = await prisma.sastIssue.update({
        where: { id: req.params.id },
        data: { notes: req.body.notes },
      });

      return sastIssueToOut(updated);
    },
  );

  // ---------------------------------------------------------------------------
  // PUT /sca-issues/:id/notes
  // ---------------------------------------------------------------------------

  typed.put(
    "/api/sca-issues/:id/notes",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["issues"],
        summary: "Set notes on a SCA issue",
        params: IdParamsSchema,
        body: z.object({ notes: z.string() }),
        response: {
          200: ScaIssueOutSchema,
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.scaIssue.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
      });
      if (!issue) return reply.code(404).send({ detail: "SCA issue not found" });

      const updated = await prisma.scaIssue.update({
        where: { id: req.params.id },
        data: { notes: req.body.notes },
      });

      return scaIssueToOut(updated);
    },
  );

  // ---------------------------------------------------------------------------
  // Jira ticket linking — SAST
  // ---------------------------------------------------------------------------

  typed.post(
    "/api/sast-issues/:id/jira-ticket",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Link a Jira ticket to a SAST issue (fetches metadata immediately)",
        params: IdParamsSchema,
        body: LinkJiraTicketBodySchema,
        response: { 200: JiraTicketOutSchema, 400: ErrorSchema, 401: ErrorSchema, 403: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.sastIssue.findFirst({ where: { id: req.params.id, orgId: orgId ?? null } });
      if (!issue) return reply.code(404).send({ detail: "SAST issue not found" });
      try {
        const ticket = await linkSastIssueToTicket(prisma, orgId, issue.id, req.body.issue_key.toUpperCase(), req.user?.id ?? null);
        return jiraTicketToOut(ticket);
      } catch (err) {
        const code = (err as { code?: string }).code;
        const msg = err instanceof Error ? err.message : String(err);
        return reply.code(code === "INVALID_KEY" || code === "NOT_CONFIGURED" ? 400 : 400).send({ detail: msg });
      }
    },
  );

  typed.delete(
    "/api/sast-issues/:id/jira-ticket",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Unlink Jira ticket from a SAST issue",
        params: IdParamsSchema,
        response: { 204: z.null(), 401: ErrorSchema, 403: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.sastIssue.findFirst({ where: { id: req.params.id, orgId: orgId ?? null } });
      if (!issue) return reply.code(404).send({ detail: "SAST issue not found" });
      await unlinkSastIssue(prisma, issue.id);
      return reply.code(204).send();
    },
  );

  // ---------------------------------------------------------------------------
  // Jira ticket linking — SCA
  // ---------------------------------------------------------------------------

  typed.post(
    "/api/sca-issues/:id/jira-ticket",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Link a Jira ticket to a SCA issue (fetches metadata immediately)",
        params: IdParamsSchema,
        body: LinkJiraTicketBodySchema,
        response: { 200: JiraTicketOutSchema, 400: ErrorSchema, 401: ErrorSchema, 403: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.scaIssue.findFirst({ where: { id: req.params.id, orgId: orgId ?? null } });
      if (!issue) return reply.code(404).send({ detail: "SCA issue not found" });
      try {
        const ticket = await linkScaIssueToTicket(prisma, orgId, issue.id, req.body.issue_key.toUpperCase(), req.user?.id ?? null);
        return jiraTicketToOut(ticket);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return reply.code(400).send({ detail: msg });
      }
    },
  );

  typed.delete(
    "/api/sca-issues/:id/jira-ticket",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["issues"],
        summary: "Unlink Jira ticket from a SCA issue",
        params: IdParamsSchema,
        response: { 204: z.null(), 401: ErrorSchema, 403: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const issue = await prisma.scaIssue.findFirst({ where: { id: req.params.id, orgId: orgId ?? null } });
      if (!issue) return reply.code(404).send({ detail: "SCA issue not found" });
      await unlinkScaIssue(prisma, issue.id);
      return reply.code(204).send();
    },
  );

  // ---------------------------------------------------------------------------
  // Jira tickets for a scope (all linked tickets, de-duplicated)
  // ---------------------------------------------------------------------------

  typed.get(
    "/api/scopes/:id/jira-tickets",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scopes", "jira"],
        summary: "List all Jira tickets linked to issues in this scope",
        params: IdParamsSchema,
        response: { 200: z.array(JiraTicketOutSchema), 401: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const scope = await prisma.scanScope.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
        select: { id: true },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      // Collect unique ticket IDs referenced by any issue in this scope
      const [sastTicketIds, scaTicketIds] = await Promise.all([
        prisma.sastIssue.findMany({ where: { scopeId: scope.id, jiraTicketId: { not: null } }, select: { jiraTicketId: true } }),
        prisma.scaIssue.findMany({ where: { scopeId: scope.id, jiraTicketId: { not: null } }, select: { jiraTicketId: true } }),
      ]);
      const ids = [...new Set([...sastTicketIds, ...scaTicketIds].map((r) => r.jiraTicketId!))];
      if (ids.length === 0) return [];
      const tickets = await prisma.jiraTicket.findMany({ where: { id: { in: ids } } });
      return tickets.map(jiraTicketToOut);
    },
  );

  // ---------------------------------------------------------------------------
  // Jira ticket on-demand refresh
  // ---------------------------------------------------------------------------

  typed.post(
    "/admin/jira-tickets/:key/refresh",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["jira"],
        summary: "Force-refresh a Jira ticket from the remote API",
        params: z.object({ key: z.string() }),
        response: { 200: JiraTicketOutSchema, 401: ErrorSchema, 403: ErrorSchema, 404: ErrorSchema },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      try {
        const ticket = await refreshTicket(prisma, orgId, req.params.key.toUpperCase());
        return jiraTicketToOut(ticket);
      } catch (err) {
        return reply.code(404).send({ detail: err instanceof Error ? err.message : String(err) });
      }
    },
  );
};

export default scopesRoutes;
