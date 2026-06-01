# Contributing to SASTBot

This guide covers **how we work**: the branching model, pull-request flow, commit
conventions, how to build and test locally, and how releases are cut. For
architecture, the versioning policy in depth, and AI-agent guidance, see
[`CLAUDE.md`](CLAUDE.md). The canonical remote is **LMI Bitbucket Cloud**.

> ⚠️ **Never commit secrets or internal identifiers.** A public GitHub mirror
> exists. Keep credentials, tokens, internal hostnames/IPs, and the Bitbucket
> workspace slug out of the tracked tree — use `.env` (gitignored), Bitbucket
> repository/workspace variables, or runtime variables like `$BITBUCKET_WORKSPACE`.

## Branching model

We use a `develop` / `main` flow:

| Branch | Role |
|--------|------|
| **`develop`** | The primary integration branch. Day-to-day work lands here. |
| **`feature/*`** (or `fix/*`, `chore/*`) | One per non-trivial change, branched off `develop`. |
| **`main`** | Release candidate **and** release branch. Tagging a commit here deploys it. |
| **`hotfix/*`** | Urgent production fixes, branched off `main`. |

```
feature/x ──┐ (rebase onto develop, then merge)
            ▼
develop ────●────●────●──────► (merge to main when ready to test)
                          \
main ──────────────────────●───●(tag vX.Y.Z = deploy)
                            ▲
hotfix/y ───────────────────┘ (off main; merge to main AND back to develop)
```

### Feature work
1. Branch off the latest `develop`: `git switch develop && git pull && git switch -c feature/short-name`.
2. Commit as you go (see [Commit messages](#commit-messages)).
3. **Before merging back, rebase onto `develop`** so history stays linear and your
   change sits on top of current work:
   ```bash
   git fetch origin
   git rebase origin/develop
   # resolve conflicts, re-run tests
   ```
4. Open a **pull request into `develop`**. CI runs the test gate on the PR; it must
   be green. Get a review, then merge.
5. **Delete the feature branch once it's merged.** Keep the branch list to the
   long-lived branches (`develop`, `main`) plus only genuinely in-flight work —
   stale merged branches accumulate and obscure what's actually active.
   ```bash
   git branch -d feature/short-name          # -d refuses unless fully merged —
                                             # doubles as a check the work landed
   git push origin --delete feature/short-name   # only if you pushed the branch
   ```

### Promoting to test / release
- **Ready to test:** merge `develop` → `main`. The push to `main` runs the test
  gate. `main` is the release candidate.
- **Ready to deploy:** make sure the version is bumped (see [Releases](#releases-and-versioning)),
  the change is on `main`, then **tag** `vX.Y.Z`. The tag triggers the image
  build + push (the deploy artifact). See [CI](#continuous-integration).

### Hotfixes
1. Branch off `main`: `git switch main && git pull && git switch -c hotfix/short-name`.
2. Fix, PR into `main`, merge. If shipping, bump the patch version and tag `vX.Y.Z`.
3. **Merge the hotfix back into `develop`** (or cherry-pick) so it isn't lost on the
   next release.

## Commit messages

We follow **[Conventional Commits](https://www.conventionalcommits.org/)**:

```
<type>(<optional scope>): <imperative, lower-case summary ≤ ~72 chars>

<optional body: what & why, wrapped ~72 cols>

<optional footers>
```

Types used in this repo: `feat`, `fix`, `chore`, `docs`, `test`, `ci`,
`refactor`, `perf`, `build`. Examples:

```
feat(scopes): add per-repo ignore_paths to the scan exclusion set
fix(ui): correct dashboard open-findings count
ci: add Postgres + Redis services to the test gate
docs: record Stage-3 completion in PROGRESS.md
```

- **Imperative mood** ("add", not "added"/"adds").
- One logical change per commit; keep them buildable.
- Reference issues/tickets in the body or a footer when relevant.
- AI-assisted commits include a `Co-Authored-By:` trailer for the model.

## Build, run, and test (local)

Full prerequisites and first-boot details are in the [README](README.md#quick-start-local).

```bash
cp .env.example .env   # once — generates a fresh MASTER_KEY (see the file)
docker compose -f docker/compose/docker-compose.yml --env-file .env up --build
```
- Frontend <http://localhost:5173> · Backend <http://localhost:8000> (`/docs`, `/openapi.json`)
- First boot prints a bootstrap admin password: `docker compose -f docker/compose/docker-compose.yml logs backend | grep BOOTSTRAP`
- `--env-file .env` is **required** (the compose file lives in `docker/compose/`).

### Tests & checks (mirror what CI runs)
```bash
# backend — typecheck + unit tests (vitest)
docker compose -f docker/compose/docker-compose.yml exec backend pnpm typecheck
docker compose -f docker/compose/docker-compose.yml exec backend pnpm test

# frontend — typecheck + unit tests
docker compose -f docker/compose/docker-compose.yml exec frontend npm run typecheck
docker compose -f docker/compose/docker-compose.yml exec frontend npm test
```

### Database migrations
```bash
# after editing backend/prisma/schema.prisma
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate dev --name describe_change
# commit the generated prisma/migrations/<timestamp>_describe_change/ folder
```
Work through [`docs/MIGRATIONS_CHECKLIST.md`](docs/MIGRATIONS_CHECKLIST.md) before
writing a migration. The migration folder **is** the schema-version bump — always
commit it.

## Releases and versioning

SASTBot tracks an **app version** (SemVer) and a **DB schema version**. Before
tagging a release, bump the app version in **all three** surfaces in one commit —
drift makes operators see lying version numbers and **fails CI** (the test gate
asserts the three agree):

1. `backend/package.json` → `version`
2. `frontend/package.json` → `version`
3. `backend/src/routes/version.ts` → `APP_VERSION`

Then refresh lockfiles (`pnpm install` / `npm install`), commit, merge to `main`,
and tag:
```bash
git tag v0.17.0      # must equal the package.json version — CI enforces this
git push origin v0.17.0
```
PATCH = bug fix · MINOR = backwards-compatible feature · MAJOR reserved for
post-1.0 breaking changes. The full policy (and the schema-migration ordering) is
in the **⚠️ Versioning policy** section of [`CLAUDE.md`](CLAUDE.md) and
[`docs/user-manual/admin-versioning.md`](docs/user-manual/admin-versioning.md).

Operator-visible changes (new screen/flow/env var/endpoint) must also update the
matching user-manual section under `docs/user-manual/` (the source of truth — the
frontend build syncs it into the app; a new page also needs a manifest entry in
`frontend/src/manual/index.ts`) and get a `docs/PROGRESS.md` entry.

## Continuous integration

CI is **Bitbucket Pipelines** (`bitbucket-pipelines.yml`). What runs where:

| Event | Pipeline |
|-------|----------|
| Pull request (any source branch) | **Test gate** — version drift guard + backend & frontend typecheck + tests |
| Push to `develop` | Test gate |
| Push to `main` | Test gate |
| Push tag `vX.Y.Z` | Test gate, then **build & push** `sastbot-backend` + `sastbot-frontend` images to the Bitbucket Packages registry (`crg.apkg.io`), tagged `latest` + `X.Y.Z` + `X.Y.Z-<sha>` |
| Manual `custom: build-and-push-images` | Test gate + build & push (on-demand) |

A PR or push must have a **green test gate** before merge.

### Container registry note (one-time, per image)
Bitbucket Packages **does not auto-create container packages on push.** Before the
first publish of a new image name, create the package in the UI
(**Create → Package**, name = the exact image name, linked to this repo); otherwise
the push fails with `name unknown … does not exist in this workspace`. Pipelines
authenticate to the registry automatically via the injected
`$BITBUCKET_PACKAGES_USERNAME` / `$BITBUCKET_PACKAGES_TOKEN` — no secret to manage.

## Code conventions (summary)

See [`CLAUDE.md`](CLAUDE.md) for the full set. Highlights:
- **Backend:** async/await only; Zod schemas are the source of truth for
  request/response shapes; services wrap Prisma and own transaction boundaries;
  no `any` outside boundary adapters.
- **Frontend:** server state via TanStack Query (typed hooks under
  `src/api/queries/`); UI-only state via Zustand; API types are generated
  (`npm run gen:types`), not hand-written.
- Keep the OpenAPI route `tags`/`summary`/`description` accurate — they are the
  protocol documentation.
