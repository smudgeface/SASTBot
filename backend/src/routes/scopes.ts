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
  ScaDismissedStatusSchema,
  ScaIssueDismissBodySchema,
  ScaIssueListSchema,
  ScaIssueOutSchema,
  SbomComponentOutSchema,
  SeveritySchema,
  FindingTypeSchema,
  UuidSchema,
} from "../schemas.js";
import { jiraTicketToOut, sastIssueToOut, scaIssueToOut, scanRunToOut, sbomComponentToOut, scopeComponentToOut } from "../services/mappers.js";
import { linkSastIssueToTicket, linkScaIssueToTicket, refreshTicket, unlinkSastIssue, unlinkScaIssue } from "../services/jiraTicketService.js";

// Query-string boolean parser. `z.coerce.boolean()` is a footgun in query-
// string contexts because Zod's coerce uses `Boolean(value)`, and
// `Boolean("false") === true` (any non-empty string is truthy in JS). That
// silently makes `?flag=false` behave the same as `?flag=true`. This helper
// parses the literal "true" / "false" strings explicitly. Use everywhere a
// query parameter might be sent with an explicit "false" value.
const queryBool = z.preprocess(
  (v) => (v === "false" ? false : v === "true" ? true : v),
  z.boolean(),
);

// ---------------------------------------------------------------------------
// Scope list / detail schemas
// ---------------------------------------------------------------------------

const ActiveScanSchema = z.object({
  id: z.string().uuid(),
  status: z.enum(["pending", "running"]),
  started_at: z.string().nullable(),
  current_phase: z.string().nullable(),
  phase_progress: z.object({
    done: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    label: z.string().optional(),
  }).nullable(),
}).nullable();

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
  /** Most recent pending/running scan for this scope, or null if no scan
   *  is in flight. Polled by the scopes list page to show live progress. */
  active_scan: ActiveScanSchema,
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
  /** Repo's source-URL template (e.g. ".../browse/$FILE#$LINE"); null if
   *  the repo has not configured one. The frontend uses this to make file
   *  paths in SAST/SCA detail views clickable. */
  source_url_template: z.string().nullable(),
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
  dismissed_status: ScaDismissedStatusSchema.optional(),
  dismissed_statuses: toArray(ScaDismissedStatusSchema),
  has_jira_ticket: z.enum(["yes", "no"]).optional(),
  reachable: z.coerce.boolean().optional(),
  has_fix: z.coerce.boolean().optional(),
  /** When true (default), hides SCA issues where latestIsDevOnly = true.
   *  Pass false to show build-tool CVEs. Gates on cdxgen 12.2+ dev marker — npm-only signal. */
  exclude_dev_only: queryBool.default(true),
  /** @deprecated Replaced by exclude_dev_only. Accepted but ignored. */
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

      // Batch-fetch the most recent pending/running scan per scope, so the
      // scopes list page can show live progress without N polls.
      const activeRuns = await prisma.scanRun.findMany({
        where: {
          scopeId: { in: scopes.map((s) => s.id) },
          status: { in: ["pending", "running"] },
        },
        orderBy: { createdAt: "desc" },
        select: {
          id: true, scopeId: true, status: true, startedAt: true,
          currentPhase: true, phaseProgress: true, createdAt: true,
        },
      });
      // First match wins (rows are sorted desc) — at most one active run per scope in practice.
      const activeByScope = new Map<string, (typeof activeRuns)[number]>();
      for (const r of activeRuns) {
        if (!activeByScope.has(r.scopeId)) activeByScope.set(r.scopeId, r);
      }

      return Promise.all(scopes.map(async (scope) => {
        const repo = scope.repo as { name: string; defaultBranch: string };

        const TERMINAL = ["suppressed", "false_positive", "fixed"] as string[];
        const activeWhere = (sev: string) => ({
          scopeId: scope.id, dismissedStatus: { notIn: TERMINAL }, latestSeverity: sev,
        });
        const activeSastWhere = (sev: string) => ({
          scopeId: scope.id, latestSeverity: sev,
          triageStatus: { notIn: TERMINAL },
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
          sastPendingCount,
          scaPendingCount,
        ] = await Promise.all([
          prisma.sastIssue.count({
            where: { scopeId: scope.id, triageStatus: { notIn: TERMINAL } },
          }),
          prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: { notIn: TERMINAL } } }),
          combined("critical"),
          combined("high"),
          combined("medium"),
          combined("low"),
          prisma.sastIssue.count({ where: { scopeId: scope.id, triageStatus: "pending" } }),
          prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: "pending" } }),
        ]);
        const pendingTriageCount = sastPendingCount + scaPendingCount;

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
          active_scan: (() => {
            const a = activeByScope.get(scope.id);
            if (!a) return null;
            return {
              id: a.id,
              status: (a.status === "pending" ? "pending" : "running") as "pending" | "running",
              started_at: a.startedAt?.toISOString() ?? null,
              current_phase: a.currentPhase,
              phase_progress: a.phaseProgress as { done: number; total: number; label?: string } | null,
            };
          })(),
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
        include: { repo: { select: { name: true, defaultBranch: true, sourceUrlTemplate: true } } },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });

      const repo = scope.repo as { name: string; defaultBranch: string; sourceUrlTemplate: string | null };
      const lastScanRunId = scope.lastScanRunId;

      const TERMINAL_D = ["suppressed", "false_positive", "fixed"] as string[];
      const activeWhereD = (sev: string) => ({
        scopeId: scope.id, dismissedStatus: { notIn: TERMINAL_D }, latestSeverity: sev,
      });
      const activeSastWhereD = (sev: string) => ({
        scopeId: scope.id, latestSeverity: sev,
        triageStatus: { notIn: TERMINAL_D },
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
        sastPendingCountD,
        scaPendingCountD,
        resolvedSastCount,
        resolvedScaCount,
        activeRun,
      ] = await Promise.all([
        prisma.sastIssue.count({
          where: { scopeId: scope.id, triageStatus: { notIn: TERMINAL_D } },
        }),
        prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: { notIn: TERMINAL_D } } }),
        combinedD("critical"),
        combinedD("high"),
        combinedD("medium"),
        combinedD("low"),
        prisma.sastIssue.count({ where: { scopeId: scope.id, triageStatus: "pending" } }),
        prisma.scaIssue.count({ where: { scopeId: scope.id, dismissedStatus: "pending" } }),
        lastScanRunId
          ? prisma.sastIssue.count({ where: { scopeId: scope.id, lastSeenScanRunId: { not: lastScanRunId } } })
          : 0,
        lastScanRunId
          ? prisma.scaIssue.count({ where: { scopeId: scope.id, lastSeenScanRunId: { not: lastScanRunId } } })
          : 0,
        prisma.scanRun.findFirst({
          where: { scopeId: scope.id, status: { in: ["pending", "running"] } },
          orderBy: { createdAt: "desc" },
          select: {
            id: true, status: true, startedAt: true,
            currentPhase: true, phaseProgress: true,
          },
        }),
      ]);
      const pendingTriageCount = sastPendingCountD + scaPendingCountD;

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
        active_scan: activeRun
          ? {
              id: activeRun.id,
              status: (activeRun.status === "pending" ? "pending" : "running") as "pending" | "running",
              started_at: activeRun.startedAt?.toISOString() ?? null,
              current_phase: activeRun.currentPhase,
              phase_progress: activeRun.phaseProgress as { done: number; total: number; label?: string } | null,
            }
          : null,
        active_sast_issue_count: activeSastCount,
        active_sca_issue_count: activeSCACount,
        critical_count: criticalCount,
        high_count: highCount,
        medium_count: mediumCount,
        low_count: lowCount,
        pending_triage_count: pendingTriageCount,
        resolved_sast_count: resolvedSastCount,
        resolved_sca_count: resolvedScaCount,
        source_url_template: repo.sourceUrlTemplate ?? null,
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

      // By default hide issues not seen in the latest scan. Include any
      // in-progress scan_runs as well so that issues just re-detected by an
      // active scan (which bumps their lastSeenScanRunId to that run's id)
      // remain visible mid-scan instead of vanishing from the tab until the
      // scope's lastScanRunId advances at finalize.
      if (!include_resolved && lastScanRunId && !seen_since_last_scan) {
        const inFlight = await prisma.scanRun.findMany({
          where: { scopeId: req.params.id, status: { in: ["pending", "running"] } },
          select: { id: true },
        });
        const validIds = [lastScanRunId, ...inFlight.map((r) => r.id)];
        where.lastSeenScanRunId = validIds.length === 1 ? validIds[0] : { in: validIds };
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
          200: PaginatedSchema(ScaIssueOutSchema).extend({
            total_dev: z.number().int().nonnegative(),
            total_runtime: z.number().int().nonnegative(),
          }),
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
        page, page_size, severity, finding_type, dismissed_status, dismissed_statuses,
        has_jira_ticket, reachable, has_fix, exclude_dev_only,
        seen_since_last_scan, include_resolved,
      } = req.query;
      const lastScanRunId = scope.lastScanRunId;

      const where: Record<string, unknown> = { scopeId: req.params.id };
      if (severity?.length)      where.latestSeverity     = severity.length === 1     ? severity[0]      : { in: severity };
      if (finding_type?.length)  where.latestFindingType  = finding_type.length === 1 ? finding_type[0]  : { in: finding_type };
      if (dismissed_statuses?.length)  where.dismissedStatus = dismissed_statuses.length === 1 ? dismissed_statuses[0] : { in: dismissed_statuses };
      else if (dismissed_status) where.dismissedStatus = dismissed_status;
      if (has_jira_ticket === "yes") where.jiraTicketId = { not: null };
      if (has_jira_ticket === "no") where.jiraTicketId = null;
      if (reachable === true) where.confirmedReachable = true;
      if (has_fix === true) where.latestHasFix = true;

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

      // By default hide issues not seen in the latest scan. Include any
      // in-progress scan_runs as well so that issues just re-detected by an
      // active scan (which bumps their lastSeenScanRunId to that run's id)
      // remain visible mid-scan instead of vanishing from the tab until the
      // scope's lastScanRunId advances at finalize.
      if (!include_resolved && lastScanRunId && !seen_since_last_scan) {
        const inFlight = await prisma.scanRun.findMany({
          where: { scopeId: req.params.id, status: { in: ["pending", "running"] } },
          select: { id: true },
        });
        const validIds = [lastScanRunId, ...inFlight.map((r) => r.id)];
        where.lastSeenScanRunId = validIds.length === 1 ? validIds[0] : { in: validIds };
      }

      // Always compute dev/runtime split counts (unaffected by exclude_dev_only filter).
      const baseWhere = { ...where };
      const [total_dev, total_runtime] = await Promise.all([
        prisma.scaIssue.count({ where: { ...baseWhere, latestIsDevOnly: true } }),
        prisma.scaIssue.count({ where: { ...baseWhere, latestIsDevOnly: false } }),
      ]);

      if (exclude_dev_only) {
        where.latestIsDevOnly = false;
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

      return { items: items.map(scaIssueToOut), total, page, page_size, total_dev, total_runtime };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/components — from the most recent scan run
  // ---------------------------------------------------------------------------

  // M6q: ScopeComponentOutSchema extends SbomComponentOutSchema with
  // linked_issue_ids (scope-level concept only; not on scan endpoint).
  // M7: the row id IS the scope_components.id — the trashcan delete passes it
  // directly, no second lookup needed.
  const ScopeComponentOutSchema = SbomComponentOutSchema.extend({
    linked_issue_ids: z.object({
      sca: z.array(z.string().uuid()),
      sast: z.array(z.string().uuid()),
    }).optional(),
  });

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
          /** When true (default), hides components with isDevOnly = true. Pass false to show build-tool packages. */
          exclude_dev_only: queryBool.default(true),
        }),
        response: {
          200: PaginatedSchema(ScopeComponentOutSchema).extend({
            total_dev: z.number().int().nonnegative(),
            total_runtime: z.number().int().nonnegative(),
          }),
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

      // Components tab reads from scope_components — the durable, deduped,
      // manually-editable truth set for this scope. Manual deletes / LLM
      // merges / lifecycle dismissals all mutate scope_components, so this
      // is the table the operator-facing list MUST reflect. Per-scan SBOM
      // history remains on sbom_components and is read by the scan-detail
      // page (which reads scan-local data only — never reverses to scope).

      const { page, page_size, has_findings, exclude_dev_only } = req.query;
      const baseWhere: Record<string, unknown> = {
        scopeId: scope.id,
        dismissedStatus: "active",
      };

      // Always compute dev/runtime split counts before applying the dev filter.
      const [total_dev, total_runtime] = await Promise.all([
        prisma.scopeComponent.count({ where: { ...baseWhere, isDevOnly: true } }),
        prisma.scopeComponent.count({ where: { ...baseWhere, isDevOnly: false } }),
      ]);

      const where = { ...baseWhere };
      if (exclude_dev_only) {
        where.isDevOnly = false;
      }

      const skip = (page - 1) * page_size;
      const [scopeRows, total] = await Promise.all([
        prisma.scopeComponent.findMany({
          where,
          orderBy: { name: "asc" },
          skip,
          take: page_size,
        }),
        prisma.scopeComponent.count({ where }),
      ]);

      // has_findings: keep only rows whose package has a sca_issue at scope
      // level. Post-query filter — scope_components has no direct join.
      let comps = scopeRows;
      if (has_findings === true) {
        const names = scopeRows.map((r) => r.name);
        if (names.length > 0) {
          const findingsRows = await prisma.scaIssue.findMany({
            where: { scopeId: scope.id, packageName: { in: names } },
            select: { packageName: true },
          });
          const withFindings = new Set(findingsRows.map((f) => f.packageName));
          comps = scopeRows.filter((r) => withFindings.has(r.name));
        }
      }

      // M6q: derive linked_issue_ids in a single batched query per endpoint call.
      // SCA: match by scopeId + packageName + lastSeenScanRunId = scope.lastScanRunId.
      // SAST: match by scopeId + reachableCallSites referencing the component's purl
      //       (narrow set; most components will have no SAST links).
      const componentNames = comps.map((c) => c.name);
      const scaIssues = componentNames.length > 0
        ? await prisma.scaIssue.findMany({
            where: {
              scopeId: scope.id,
              packageName: { in: componentNames },
            },
            select: { id: true, packageName: true },
          })
        : [];

      // Build map: componentName → sca issue ids
      const scaByName = new Map<string, string[]>();
      for (const issue of scaIssues) {
        const existing = scaByName.get(issue.packageName) ?? [];
        existing.push(issue.id);
        scaByName.set(issue.packageName, existing);
      }

      // Per-scan `occurrences` is no longer fetched: legacy data was lifted
      // into scope_components.evidence_paths by migration
      // 20260515123000_backfill_evidence_paths_from_occurrences, and the
      // Components UI now renders solely from scope_components fields.

      return {
        items: comps.map((c) => ({
          ...scopeComponentToOut(c),
          linked_issue_ids: {
            sca: scaByName.get(c.name) ?? [],
            sast: [], // SAST-to-component links are rare; populated in future if needed
          },
        })),
        total,
        page,
        page_size,
        total_dev,
        total_runtime,
      };
    },
  );

  // ---------------------------------------------------------------------------
  // DELETE /scopes/:id/components/:componentId — manual component removal
  // ---------------------------------------------------------------------------
  //
  // Operator-driven cleanup for residual dup rows the deterministic matcher
  // doesn't catch (LLM naming variants that elude every tier of the chain,
  // legacy rows pre-dating component_root, etc.). Hard delete — cascades the
  // scan_run_components join table. sbom_components is per-scan audit and is
  // untouched. The next scan re-emits real components; the componentMatch
  // chain collapses them into the canonical row, so this is safe to use
  // freely.

  typed.delete(
    "/api/scopes/:id/components/:componentId",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["scopes"],
        summary: "Delete a scope component (manual cleanup of dup rows)",
        params: z.object({ id: UuidSchema, componentId: UuidSchema }),
        response: {
          204: z.null(),
          401: ErrorSchema,
          403: ErrorSchema,
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

      const component = await prisma.scopeComponent.findFirst({
        where: { id: req.params.componentId, scopeId: scope.id },
        select: { id: true, name: true },
      });
      if (!component) return reply.code(404).send({ detail: "Component not found in this scope" });

      await prisma.scopeComponent.delete({ where: { id: component.id } });
      return reply.code(204).send();
    },
  );

  // ---------------------------------------------------------------------------
  // PATCH /scopes/:id/components/:componentId — manual edits
  // ---------------------------------------------------------------------------
  //
  // Operator-driven update of identity fields on a scope_component. Used to
  // backfill or correct component_root and evidence_paths when the LLM picked
  // something wrong (or didn't pick anything at all on older rows). Setting
  // `source = 'manual_override'` is intentional: marking the row as operator-
  // managed prevents the next scan's auto-upsert from overwriting the values
  // (persistScanComponentsToScopeState explicitly skips manual_override rows).

  const PatchComponentBodySchema = z.object({
    name: z.string().min(1).optional(),
    component_root: z.string().nullable().optional(),
    /** Each entry is {path, line?}. The frontend submits a parsed form from
     *  a textarea that allows `path:line` shorthand on each line. */
    evidence: z
      .array(
        z.object({
          path: z.string().min(1),
          line: z.number().int().positive().nullable().optional(),
        }),
      )
      .optional(),
  });

  typed.patch(
    "/api/scopes/:id/components/:componentId",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["scopes"],
        summary: "Edit a scope component's identity fields (component_root, evidence_paths)",
        params: z.object({ id: UuidSchema, componentId: UuidSchema }),
        body: PatchComponentBodySchema,
        response: {
          200: z.object({ ok: z.literal(true) }),
          401: ErrorSchema,
          403: ErrorSchema,
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

      const component = await prisma.scopeComponent.findFirst({
        where: { id: req.params.componentId, scopeId: scope.id },
        select: { id: true },
      });
      if (!component) return reply.code(404).send({ detail: "Component not found in this scope" });

      const data: Record<string, unknown> = { source: "manual_override" };
      if (req.body.name !== undefined) {
        const trimmed = req.body.name.trim();
        if (trimmed === "") {
          return reply.code(400).send({ detail: "name cannot be blank" });
        }
        data.name = trimmed;
      }
      if (req.body.component_root !== undefined) {
        // Normalize blank string to null.
        const trimmed = req.body.component_root?.trim() ?? null;
        data.componentRoot = trimmed === "" ? null : trimmed;
      }
      if (req.body.evidence !== undefined) {
        // Preserve order; dedupe by trimmed path (line is diagnostic so
        // first-wins). Empty paths are filtered.
        const seen = new Set<string>();
        const cleaned: Array<{ path: string; line: number | null }> = [];
        for (const e of req.body.evidence) {
          const p = e.path.trim();
          if (p === "" || seen.has(p)) continue;
          seen.add(p);
          cleaned.push({ path: p, line: e.line ?? null });
        }
        data.evidence = cleaned;
      }

      try {
        await prisma.scopeComponent.update({
          where: { id: component.id },
          data,
        });
      } catch (err) {
        // P2002 = unique constraint violation. Rename collided with an
        // existing (scope_id, name, version, purl) row. Return a useful
        // message; operator can delete the duplicate first if they want to
        // proceed with the rename.
        const code = (err as { code?: string }).code;
        if (code === "P2002") {
          return reply.code(400).send({
            detail: "A component with this name + version + purl already exists in this scope. Delete the duplicate first, then rename.",
          });
        }
        throw err;
      }

      return { ok: true as const };
    },
  );

  // ---------------------------------------------------------------------------
  // GET /scopes/:id/sbom-json — download SBOM for the most recent scan
  // ---------------------------------------------------------------------------

  // M6q: scope-level SBOM download. Returns sbom_json for the scope's
  // lastScanRunId. Mirrors GET /scans/:id/sbom on the scan page.
  app.get(
    "/api/scopes/:id/sbom-json",
    {
      preHandler: [app.authenticate],
    },
    async (req, reply) => {
      const orgId = (req as unknown as { user?: { orgId?: string } }).user?.orgId ?? null;
      const params = req.params as { id: string };

      const scope = await prisma.scanScope.findFirst({
        where: { id: params.id, orgId: orgId ?? null },
        select: {
          id: true,
          lastScanRunId: true,
          path: true,
          repo: { select: { name: true } },
        },
      });
      if (!scope) return reply.code(404).send({ detail: "Scope not found" });
      if (!scope.lastScanRunId) return reply.code(404).send({ detail: "No successful scan for this scope" });

      // Build from the curated sbom_components rows (M6q follow-up: don't
      // serve the raw cdxgen output, which contains CMake find_package
      // probes + absolute "Filename /app/clones/..." paths that bypass
      // the M6q CWD fix).
      const { buildCuratedSbomJson } = await import("../services/sbomCurated.js");
      const doc = await buildCuratedSbomJson(scope.lastScanRunId);
      if (!doc) return reply.code(404).send({ detail: "SBOM not yet available for this scan" });

      const repoName = (scope.repo as { name: string }).name;
      // Build a slug from the scope path: "/" → "root", "/GoWeb" → "GoWeb"
      const scopeSlug = scope.path === "/" ? "root" : scope.path.replace(/^\//, "").replace(/\//g, "-");
      const filename = `sbom-${repoName}-${scopeSlug}.cdx.json`;
      const pretty = JSON.stringify(doc, null, 2);
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="${filename}"`)
        .send(pretty);
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
            current_phase: z.string().nullable(),
            phase_progress: z.object({
              done: z.number().int().nonnegative(),
              total: z.number().int().nonnegative(),
              label: z.string().optional(),
            }).nullable(),
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
          currentPhase: true, phaseProgress: true,
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
        current_phase: r.currentPhase,
        phase_progress: r.phaseProgress as { done: number; total: number; label?: string } | null,
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
      const isReopen = status === "pending";
      const updated = await prisma.scaIssue.update({
        where: { id: req.params.id },
        data: {
          dismissedStatus: status,
          dismissedReason: isReopen ? null : (reason ?? null),
          dismissedAt: isReopen ? null : new Date(),
          dismissedByUserId: isReopen ? null : (req.user?.id ?? null),
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
