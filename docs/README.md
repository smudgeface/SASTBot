# SASTBot documentation map

This is the index for everything under `docs/`. Start here to find the right doc, and to
know where a new doc belongs.

`CLAUDE.md` (repo root) is the lean contributor/agent guide — versioning policy, dev
workflow, conventions. It points here for everything deeper.

## Living docs — kept current, read before changing the relevant subsystem

| Doc | What it is |
|-----|------------|
| [`PROGRESS.md`](PROGRESS.md) | Chronological milestone log. One entry per milestone, dated, "what shipped" + "what we learned". The written-down compression of project context — append, never rewrite. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Subsystem notes & hard-won invariants (scan pipeline, SCA/SBOM, SAST, two-table component model, routing). Read the matching note before touching a subsystem. |
| [`SCAN_LIFECYCLE.md`](SCAN_LIFECYCLE.md) | The scan-run state machine and phase ordering. |
| [`MIGRATIONS_CHECKLIST.md`](MIGRATIONS_CHECKLIST.md) | Work through this **before** writing any Prisma migration — renames, NOT NULL on populated tables, big-table locking, JSON shape changes, the worker-backfill contract. |
| [`OPERATIONS.md`](OPERATIONS.md) | Ops runbook. |
| [`DEPLOY_PROXMOX.md`](DEPLOY_PROXMOX.md) | Current production deployment guide (Proxmox + Bitbucket Packages). |
| [`user-manual/`](user-manual/) | The operator manual — **canonical source of truth**, synced into the SPA at `/manual/*` by the frontend build. One section per file; manifest is `frontend/src/manual/index.ts`. Keep current with any operator-visible change. |
| [`Claude CRA Analysis Reference/`](Claude%20CRA%20Analysis%20Reference/) | Reference material for EU CRA compliance (prompt, sample report, sample SBOM). |

Two deploy docs are **gitignored** (personal infra, kept local only): `DEPLOY_HOMELAB.md`
and `DEPLOY_DOKPLOY_*.md`. They never enter the tracked tree — see the
"keep internal details out of the repo" rule in `CLAUDE.md`.

## `memory/` — historical records

[`memory/`](memory/) holds **completed** milestone plans, design handoffs, audits, and
superseded guides. These are kept for provenance and the occasional "why did we do it this
way" archaeology — they are **not** maintained and may describe code that has since changed.
Treat them as point-in-time snapshots, not current truth; when a memory doc and a living doc
disagree, the living doc (or the code) wins.

### What lives there

- **Milestone plans** — `M4_PLAN.md` … `M18_MEMBER_ROLE_PLAN.md` (the `M*_PLAN.md` /
  `M*_HANDOFF.md` family), plus `M6o_UI_AUDIT.md`.
- **Design/handoff docs for shipped features** — `HANDOFF_COMPONENT_ACCURACY.md`,
  `SBOM_COMPONENT_RECHECK_PLAN.md`, `SBOM_STAGE_CONTRACT_PLAN.md`.
- **Production-readiness work** — `PROD_READINESS_PLAN.md`, `PROD_READINESS_AUDIT.md`.
- **Superseded deploy guides** — `HOW_TO_DEPLOY_WEB_APP_ON_DOKPLOY.md` (Dokploy era,
  replaced by `DEPLOY_PROXMOX.md`).

> Note: `PROGRESS.md` still references some of these plans by their old `docs/<NAME>.md`
> path in dated historical entries. Those mentions are left intact as part of the record —
> the file now lives under `docs/memory/<NAME>.md`.

### When to add to `memory/`

When a milestone or design effort is **done** — its plan executed, the feature shipped, the
audit closed — move its planning/handoff doc here:

```bash
git mv docs/M19_SOMETHING_PLAN.md docs/memory/
```

Then add a line to the appropriate group above. Rule of thumb: if a doc describes work to be
done (a plan, an audit, a handoff) and that work is complete, it's a memory. If a doc
describes how the system works *now* or how to operate it, it stays a living doc at the top
level.
