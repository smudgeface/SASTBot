/**
 * Jira ticket linking and sync service.
 *
 * JiraTicket rows are a cache of remote Jira state. One JiraTicket can link to
 * many SastIssue / ScaIssue rows (e.g. a "fix lodash" ticket covers multiple CVEs).
 * Unlinking an issue leaves the JiraTicket row intact; it is GC'd manually or on
 * org delete. This matches the plan: no issue creation from SASTBot, read-only only.
 */
import type { JiraTicket, Prisma, PrismaClient } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import {
  fetchTicket,
  fetchTicketsBatch,
  isValidIssueKey,
  loadJiraConfig,
  type JiraTicketMeta,
} from "./jiraClient.js";

const logger = pino({ level: loadConfig().logLevel, name: "jiraTicketService" });

type Db = PrismaClient;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function metaToData(meta: JiraTicketMeta): Prisma.JiraTicketUpdateInput {
  return {
    issueId: meta.issueId,
    projectKey: meta.projectKey,
    projectName: meta.projectName,
    summary: meta.summary,
    status: meta.status,
    statusCategory: meta.statusCategory,
    resolution: meta.resolution,
    assigneeName: meta.assigneeName,
    assigneeEmail: meta.assigneeEmail,
    fixVersions: meta.fixVersions,
    issueType: meta.issueType,
    url: meta.url,
    resolvedAt: meta.resolvedAt,
    lastSyncedAt: new Date(),
    syncError: null,
  };
}

async function upsertJiraTicket(
  db: Db,
  orgId: string | null,
  issueKey: string,
  meta: JiraTicketMeta,
  linkedByUserId?: string | null,
): Promise<JiraTicket> {
  return db.jiraTicket.upsert({
    where: { uq_jira_tickets_org_key: { orgId: orgId ?? "", issueKey } },
    create: {
      orgId,
      issueKey,
      linkedByUserId,
      ...metaToData(meta),
    } as Prisma.JiraTicketCreateInput,
    update: metaToData(meta),
  });
}

// ---------------------------------------------------------------------------
// Link / unlink
// ---------------------------------------------------------------------------

export async function linkSastIssueToTicket(
  db: Db,
  orgId: string | null,
  sastIssueId: string,
  issueKey: string,
  userId: string | null,
): Promise<JiraTicket> {
  if (!isValidIssueKey(issueKey)) {
    throw Object.assign(new Error(`Invalid Jira issue key: "${issueKey}"`), { code: "INVALID_KEY" });
  }

  const cfg = await loadJiraConfig(orgId);
  if (!cfg) throw Object.assign(new Error("Jira is not configured"), { code: "NOT_CONFIGURED" });

  // Fetch from Jira immediately so we fail loudly if the key doesn't exist
  let meta: JiraTicketMeta;
  try {
    meta = await fetchTicket(cfg, issueKey);
  } catch (err) {
    throw Object.assign(
      new Error(`Jira returned error for "${issueKey}": ${err instanceof Error ? err.message : String(err)}`),
      { code: "JIRA_ERROR" },
    );
  }

  const ticket = await upsertJiraTicket(db, orgId, issueKey, meta, userId);
  // Only auto-transition pending/confirmed → planned. Issues in any other
  // state (fixed/false_positive/suppressed) keep their current status; the
  // ticket link alone shouldn't reopen a closed issue.
  const current = await db.sastIssue.findUnique({ where: { id: sastIssueId }, select: { triageStatus: true } });
  const autoPlanned = current && (current.triageStatus === "pending" || current.triageStatus === "confirmed");
  await db.sastIssue.update({
    where: { id: sastIssueId },
    data: autoPlanned
      ? { jiraTicketId: ticket.id, triageStatus: "planned" }
      : { jiraTicketId: ticket.id },
  });
  logger.info({ sastIssueId, issueKey, autoPlanned }, "[jiraTicketService] SAST issue linked to Jira ticket");
  return ticket;
}

export async function unlinkSastIssue(db: Db, sastIssueId: string): Promise<void> {
  // Only auto-transition planned → confirmed. Terminal / other statuses keep
  // their current value — unlinking shouldn't reopen a closed issue.
  const current = await db.sastIssue.findUnique({ where: { id: sastIssueId }, select: { triageStatus: true } });
  await db.sastIssue.update({
    where: { id: sastIssueId },
    data: current?.triageStatus === "planned"
      ? { jiraTicketId: null, triageStatus: "confirmed" }
      : { jiraTicketId: null },
  });
}

export async function linkScaIssueToTicket(
  db: Db,
  orgId: string | null,
  scaIssueId: string,
  issueKey: string,
  userId: string | null,
): Promise<JiraTicket> {
  if (!isValidIssueKey(issueKey)) {
    throw Object.assign(new Error(`Invalid Jira issue key: "${issueKey}"`), { code: "INVALID_KEY" });
  }

  const cfg = await loadJiraConfig(orgId);
  if (!cfg) throw Object.assign(new Error("Jira is not configured"), { code: "NOT_CONFIGURED" });

  let meta: JiraTicketMeta;
  try {
    meta = await fetchTicket(cfg, issueKey);
  } catch (err) {
    throw Object.assign(
      new Error(`Jira returned error for "${issueKey}": ${err instanceof Error ? err.message : String(err)}`),
      { code: "JIRA_ERROR" },
    );
  }

  const ticket = await upsertJiraTicket(db, orgId, issueKey, meta, userId);
  // Only auto-transition pending/confirmed → planned. Issues in any other
  // state keep their current status; linking a ticket to a closed issue
  // shouldn't reopen it.
  const current = await db.scaIssue.findUnique({ where: { id: scaIssueId }, select: { dismissedStatus: true } });
  const autoPlanned = current && (current.dismissedStatus === "pending" || current.dismissedStatus === "confirmed");
  await db.scaIssue.update({
    where: { id: scaIssueId },
    data: autoPlanned
      ? { jiraTicketId: ticket.id, dismissedStatus: "planned" }
      : { jiraTicketId: ticket.id },
  });
  logger.info({ scaIssueId, issueKey, autoPlanned }, "[jiraTicketService] SCA issue linked to Jira ticket");
  return ticket;
}

export async function unlinkScaIssue(db: Db, scaIssueId: string): Promise<void> {
  // Only auto-transition planned → confirmed. Other statuses stay put.
  const current = await db.scaIssue.findUnique({ where: { id: scaIssueId }, select: { dismissedStatus: true } });
  await db.scaIssue.update({
    where: { id: scaIssueId },
    data: current?.dismissedStatus === "planned"
      ? { jiraTicketId: null, dismissedStatus: "confirmed" }
      : { jiraTicketId: null },
  });
}

// ---------------------------------------------------------------------------
// On-demand refresh
// ---------------------------------------------------------------------------

export async function refreshTicket(
  db: Db,
  orgId: string | null,
  issueKey: string,
): Promise<JiraTicket> {
  const cfg = await loadJiraConfig(orgId);
  if (!cfg) throw new Error("Jira is not configured");

  let meta: JiraTicketMeta;
  try {
    meta = await fetchTicket(cfg, issueKey);
  } catch (err) {
    // Record the error but don't delete the ticket
    const ticket = await db.jiraTicket.findFirst({
      where: { orgId: orgId ?? null, issueKey },
    });
    if (ticket) {
      return db.jiraTicket.update({
        where: { id: ticket.id },
        data: { syncError: err instanceof Error ? err.message : String(err), lastSyncedAt: new Date() },
      });
    }
    throw err;
  }

  const existing = await db.jiraTicket.findFirst({ where: { orgId: orgId ?? null, issueKey } });
  if (!existing) throw new Error(`JiraTicket not found for key ${issueKey}`);
  return db.jiraTicket.update({ where: { id: existing.id }, data: metaToData(meta) });
}

// ---------------------------------------------------------------------------
// Scheduled sync (called by the scheduler tick in Phase 5d)
// ---------------------------------------------------------------------------

export async function reconcileJiraSync(
  db: Db,
  now: Date = new Date(),
): Promise<{ synced: number; errors: number }> {
  const OPEN_STALE_MS = 15 * 60 * 1000;   // 15 min for open tickets
  const DONE_STALE_MS = 60 * 60 * 1000;   // 60 min for done tickets

  // Find all orgs that have Jira configured
  const settings = await (db as PrismaClient).appSettings.findMany({
    where: { jiraCredentialId: { not: null }, jiraBaseUrl: { not: null }, jiraEmail: { not: null } },
    select: { orgId: true },
  });

  let synced = 0;
  let errors = 0;

  for (const { orgId } of settings) {
    const cfg = await loadJiraConfig(orgId);
    if (!cfg) continue;

    const openCutoff = new Date(now.getTime() - OPEN_STALE_MS);
    const doneCutoff = new Date(now.getTime() - DONE_STALE_MS);

    const tickets = await db.jiraTicket.findMany({
      where: {
        orgId: orgId ?? null,
        OR: [
          { statusCategory: { not: "done" }, OR: [{ lastSyncedAt: null }, { lastSyncedAt: { lt: openCutoff } }] },
          { statusCategory: "done", lastSyncedAt: { lt: doneCutoff } },
        ],
      },
    });

    if (tickets.length === 0) continue;

    const keys = tickets.map((t) => t.issueKey);
    const batchResult = await fetchTicketsBatch(cfg, keys).catch((err) => {
      logger.error({ err, orgId }, "[jiraTicketService] batch fetch failed");
      return null;
    });
    if (!batchResult) { errors += keys.length; continue; }

    for (const ticket of tickets) {
      const result = batchResult.get(ticket.issueKey);
      if (!result) {
        await db.jiraTicket.update({
          where: { id: ticket.id },
          data: { syncError: "Ticket not returned in batch", lastSyncedAt: now },
        });
        errors++;
        continue;
      }
      if ("error" in result) {
        await db.jiraTicket.update({
          where: { id: ticket.id },
          data: { syncError: result.error, lastSyncedAt: now },
        });
        errors++;
        continue;
      }
      await db.jiraTicket.update({ where: { id: ticket.id }, data: metaToData(result) });
      synced++;
    }
  }

  logger.info({ synced, errors }, "[jiraTicketService] reconcile complete");
  return { synced, errors };
}
