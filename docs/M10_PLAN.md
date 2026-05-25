# M10 — User manual + API protocol reference

> **Status:** in progress (2026-05-24)
> **Trigger:** user manual is a prod-readiness deliverable for the homelab → LMI Dokploy → LMI private GitHub deploy trajectory. Operators at LMI will both use AND administer SASTBot, so the manual must cover both roles.

## Goals

1. **In-app user manual** at `/manual/*` covering all functionality. Public route (no login required) — first-boot operators need to read it before they can log in.
2. **Protocol reference** driven by `/api/openapi.json` at view time so the docs cannot drift from the backend schema.
3. **Top-bar help icon + footer link** as the two entry points (sidebar help icon + bottom-of-sidebar "Manual" link, since the app has no top bar in the literal sense — the sidebar header row is the equivalent).
4. **CLAUDE.md pin** so future agents know the manual must be updated alongside any operator-visible code change.
5. **Hosted by the same frontend container** — no new service. Markdown source bundled into the SPA; `remark-gfm` enables tables and task lists.

## Non-goals

- Multilingual content. English only for v0.10.0.
- A separate docs build pipeline (Docusaurus, etc.). Vite ships the markdown as static asset imports.
- API client SDK generation. Operators read the protocol ref to call endpoints directly; SDK generation is a separate future deliverable.
- Versioned docs (every released version gets its own historical manual). The manual lives with the code — `git checkout v0.x.0` is the path to the historical version.

## Implementation outline

### Frontend pieces

| Piece | File(s) | Notes |
|---|---|---|
| Markdown viewer route | `frontend/src/routes/manual/ManualPage.tsx` | Two-pane layout: TOC sidebar (left, ~240px) + content (right). Renders the active section. Anchors per heading for deep-linking. |
| Markdown source | `frontend/src/manual/content/*.md` (raw-imported via Vite `?raw`) | One file per section. Linked from a manifest in `frontend/src/manual/index.ts` (title, slug, body). |
| Section component | `frontend/src/routes/manual/ManualSection.tsx` | Wraps `react-markdown` + `remark-gfm`. Internal links to other sections rewritten to in-app routes. |
| API reference | `frontend/src/routes/manual/ApiReferencePage.tsx` | Fetches `/api/openapi.json` via React Query. Groups paths by `tags[0]`. Each row expandable for parameters / request body / responses. Filter by method + free-text search. ~200 lines. |
| Help-icon entry | `frontend/src/components/AppShell.tsx` (existing) | Add `BookOpen` (or `HelpCircle`) icon to the sidebar header row next to the SASTBot logo. Links to `/manual`. |
| Footer link | `frontend/src/components/AppShell.tsx` (existing) | Add a "Manual" text link under the version block in the sidebar footer. |
| Login-page link | `frontend/src/routes/LoginPage.tsx` (existing) | Add a "Read the manual" link under the form so unauthenticated operators can find quick-start. |
| Public route | `frontend/src/App.tsx` | `/manual` and `/manual/:slug` mounted OUTSIDE the `RequireAuth` wrapper. Renders inside a stripped-down shell (logo + theme toggle, no sidebar nav for unauthenticated users). |

### Dependencies to add

- `react-markdown` — small (~30 kB gz), unopinionated markdown → React renderer.
- `remark-gfm` — GitHub-flavored markdown extension (tables, strikethrough, task lists).

No swagger-ui-react / redoc. The OpenAPI rendering is custom (~200 LOC) and matches the manual's look-and-feel.

### Manual content (one .md per file)

| Slug | Title | Audience | Purpose |
|---|---|---|---|
| `index` | Welcome to SASTBot | All | Landing page: what SASTBot is, who it's for, link map. |
| `quick-start` | Quick start | New operators | Get from zero → first scan in <15 min. References bootstrap admin password trick. |
| `overview` | How SASTBot works | All | Architecture: scopes, scans, SBOM, SAST/SCA pipelines, LLM agent role. No code. |
| `repositories` | Adding repositories | Admins + users | Repo CRUD, scan paths, ignore paths, scope auto-creation. |
| `scopes` | Working with scopes | Primary UX | Scopes list, scope detail tabs (SCA / SAST / Components), filtering, search, status transitions. |
| `scans` | Running and reading scans | All | Manual scan, scheduled scans (M5d pending), phase progress, scan warnings, the audit-view scan detail page. |
| `sca-issues` | SCA findings (CVEs) | All | Severity, reachability, dev-only suppression, dismiss flow, Jira link, dismissal reasons. |
| `sast-issues` | SAST findings (CWEs) | All | LLM detection vs recheck, confidence, snippet rendering, triage statuses, source-link template. |
| `components-sbom` | Components and SBOM | All | What lives in the Components tab; per-scope vs per-scan SBOM endpoints; CycloneDX export; CRA-evidence shape. |
| `jira` | Jira integration | All | Read-only Jira, ticket linking, status reflection, search-by-key. |
| `credentials` | Managing credentials | Admins | Credential kinds (jira_token, llm_api_key, nvd_api_key, https_basic, https_token, ssh_key), encryption posture, rotation. |
| `admin-settings` | Admin: settings page | Admins | Jira config, LLM gateway, reachability minimum severity, NVD key, save-and-test flow. |
| `admin-backup-restore` | Admin: backup and restore | Admins | Tarball layout, dump format version, full vs runtime-only restore modes, recovery scenarios. |
| `admin-versioning` | Admin: versioning and upgrades | Admins | App version vs schema version, the three surfaces, what `/version` reports, upgrade-then-restore flow. |
| `admin-deployment` | Admin: deployment | Admins | Docker compose, MASTER_KEY, artifact/clone volumes, env vars, prod entrypoint, behind-traefik notes. |
| `troubleshooting` | Troubleshooting | All | Common scan warnings (cdxgen_failed, llm_sast_detection_failed, scope_path_missing), VPN reachability, clone failures. |
| `api-reference` | Protocol reference | Integrators | Live-rendered from /api/openapi.json. Filter by method/tag, expand for parameters + responses. |

### Screenshots (small set)

Captured via Chrome DevTools, stored under `frontend/src/manual/assets/`:

- `scopes-overview.png` — `/scopes` with the FSS / GOC scopes visible.
- `scope-detail-sca.png` — scope detail page on SCA tab with at least one expanded issue.
- `sast-sarif-viewer.png` — `/scans/:id/sast-sarif` JSON viewer.

Three only. Each ~150–250 KB. The bundled markdown total stays well under 2 MB.

### CLAUDE.md pin

Add to "For AI agents" section, formatted like the existing 🔖 versioning pin:

> 📖 **Keep the user manual current.** When a code change is operator-visible (new screen, changed flow, new env var, new endpoint, new admin action) update the matching section under `frontend/src/manual/content/`. Manual drift is a worse bug than no manual — users will follow stale instructions and assume the app is broken. After ship, smoke-test the affected section in a browser. Protocol-ref content is automatic (driven by `/api/openapi.json`), but tags/summaries on routes must stay accurate.

## Version bump

`0.9.8 → 0.10.0` (MINOR — first operator-visible feature in the 0.10 line). Three files + lockfile per policy.

## Exit criteria

- [ ] All 16 narrative sections written. No section is a stub.
- [ ] API reference page renders the live openapi.json with all current endpoints.
- [ ] Help icon + footer link both reach `/manual`. Login page has its own manual link.
- [ ] `/manual` is reachable WITHOUT a login session (verified via Chrome DevTools incognito).
- [ ] All three screenshots present and embedded.
- [ ] CLAUDE.md pin added.
- [ ] PROGRESS.md entry written.
- [ ] Backend + frontend tests still green (no regressions).
- [ ] Browser smoke-test: navigate to every section + the API reference; confirm no 404s, no React errors.

## Out of scope (queued)

- M5d Scheduler, M5e Hardening — feature work, parked.
- Data export / delete — pending feature, parked.
- Multilingual manual.
- A "search" feature inside the manual. Browser Ctrl-F works fine for v0.10.0.
