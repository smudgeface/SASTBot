/**
 * Capability helpers — the single place the UI decides what a role may do.
 *
 * Privilege ladder: user < member < admin.
 *  - `user`   reads everything + adds notes.
 *  - `member` also works the triage queue: triage SAST, dismiss SCA, link/
 *    unlink/refresh Jira tickets, and modify/hide scope components.
 *  - `admin`  also touches configuration (repos, credentials, settings, users,
 *    backup/restore, key rotation) and controls scans (trigger/cancel/delete).
 *
 * These mirror the backend gates (`requireMember` / `requireAdmin`). They are
 * defense-in-depth for the UX (hide buttons a role can't use) — the backend is
 * the authoritative gate; never rely on these alone for security.
 */
import type { Role } from "@/api/types";

/** member or admin — may mutate finding/Jira/component state. */
export function canModifyFindings(role: Role | undefined | null): boolean {
  return role === "admin" || role === "member";
}

/** admin only — may touch configuration and control scans. */
export function canAdminister(role: Role | undefined | null): boolean {
  return role === "admin";
}
