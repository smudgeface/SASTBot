# Deploying a Compose-based web app to Dokploy

This guide is for engineers deploying a Node.js (or similar) web app with
Postgres and Redis to a self-hosted Dokploy instance for the first time.
It distils the lessons from an end-to-end trial and covers the four classes
of build failure you are most likely to hit, plus the operator quirks that
are nowhere in the docs.

> **Scope.** This is a guide, not a tutorial from scratch. It assumes you
> already know Docker Compose and have a running Dokploy instance.

---

## Mental model

Dokploy wraps `docker compose` with a UI that handles:

- Pulling the git repo on every deploy trigger.
- Running `docker compose up -d --build --remove-orphans` against your
  compose file.
- Fronting every stack with **Traefik**, which can terminate HTTPS and route
  traffic to containers by hostname — but you can bypass Traefik entirely for
  internal tools (see below).
- Storing secrets and runtime env vars in its own database and injecting
  them into the compose environment — there is no `.env` file on the deploy
  host.

The key consequence: **your container sees all env vars at runtime, not at
build time.** The compose env editor is the single source of truth; your
`.env.example` documents what is needed but the `.env` file itself never
lands on the server.

### Choosing a routing model

There are two practical options:

**Option A — Direct IP:port (recommended for internal-only tools)**

Publish a host port on your web server container. Users access the app at
`http://<dokploy-host-ip>:<port>`. No hostname, no DNS record, no TLS
ceremony. This is the right default for tools that are only ever accessed
over VPN or on the corporate LAN.

```yaml
services:
  frontend:
    ports:
      - "8080:80"    # host port 8080 → container port 80
```

Pick a port that isn't already in use on the host. You are responsible for
avoiding collisions between stacks deployed on the same Dokploy node.

**Option B — Traefik + hostname routing (use when you need TLS or a clean URL)**

Do not publish a host port. Dokploy's Traefik proxy routes traffic by
`Host:` header. You register a domain (or split-horizon DNS record), point
it at the Dokploy host, and configure the hostname in the Dokploy Domains
UI. Traefik handles TLS via Let's Encrypt (requires externally-resolvable
DNS for the HTTP-01 challenge) or a cert you supply.

```yaml
services:
  frontend:
    expose:
      - "80"
    # no ports: block — Traefik reaches the container on the internal network
```

Most internal LMI tools that are never exposed outside the VPN should use
**Option A**. The rest of this guide covers both; sections that are
Traefik-specific are labelled accordingly.

---

## Structuring your Compose file for Dokploy

### Compose file location

Dokploy can read a compose file at any path in the repo. Configure the
path in the Dokploy UI under the Application settings. Keep it in a
subdirectory (e.g. `docker/compose/docker-compose.prod.yml`) rather than
at the root so local dev `docker compose` invocations don't accidentally
pick it up.

### Port publishing (Option A vs. Option B)

**Option A — Direct IP:port:** publish exactly one host port on your web
server container. Everyone accesses the app via `http://<host>:<port>`.
Pick a port unique to this stack on the Dokploy host:

```yaml
services:
  frontend:
    ports:
      - "8080:80"
```

**Option B — Traefik hostname routing:** omit the `ports:` block. Traefik
reaches the container through the compose network by service name. If you
publish a port AND register a Traefik domain for the same service, you end
up with two entry points at different URLs — usually not what you want.

```yaml
services:
  frontend:
    expose:
      - "80"
    # no ports:
```

Internal databases and queues (Postgres, Redis) should never have host
ports in a production compose unless you specifically need external DBA
access, and even then, bind to `127.0.0.1` and tunnel.

### Build target must be `prod`

If your Dockerfile uses multi-stage builds, tell Dokploy which target to
build. In the compose file:

```yaml
services:
  backend:
    build:
      context: ../..
      dockerfile: docker/backend.Dockerfile
      target: prod
```

Without `target:`, Docker builds the last stage by default. This is often
your `dev` stage — it may work, but it wastes cache and ships dev tooling.

### Healthcheck-gated `depends_on`

Services that need the database ready before starting should use condition
checks:

```yaml
services:
  backend:
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  postgres:
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
```

`$$` escapes `$` from compose interpolation; the healthcheck shell sees a
single `$`.

### URL-safe database password

If you build `DATABASE_URL` from individual vars in the compose file:

```yaml
DATABASE_URL: postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}
```

The template does **no percent-encoding**. Any URL-reserved character in
`DB_PASSWORD` — `/`, `@`, `:`, `?`, `#`, `&`, `%` — will corrupt the URL
and cause Prisma (or whatever ORM you use) to reject it with an
incomprehensible parse error like `P1013: invalid port number`.

**Options (choose one):**

1. Restrict passwords to alphanumerics + `_-.~`. Regenerate if needed;
   see [Volume rotation](#rotating-a-database-password) below.
2. Accept `DATABASE_URL` as a single env var from the operator and
   percent-encode the password there. This removes the foot-gun entirely.

### Volumes

Declare named volumes for state that must survive a redeploy:

```yaml
volumes:
  pgdata:
  redisdata:
  repo_cache:   # or whatever persistent scratch space you need
```

Dokploy does **not** delete volumes when you click Redeploy — only
`docker compose down -v` does that. This is the right default: you do not
want to wipe your database on every deploy.

---

## Structuring your Dockerfiles for Dokploy

### Multi-stage layout

A typical Node + Postgres app needs three build targets:

```
base       — installs system deps, sets up the package manager
  ↓ dev    — for local docker compose dev (tsx watch, etc.)
  ↓ build  — compiles TypeScript, prunes dev deps
  ↓ prod   — minimal runtime image (copies compiled output from build)
```

The `prod` stage is what Dokploy runs.

### Pin every externally-fetched tool

`docker build` runs against the registry as it is at the moment of the
build. `@latest` is unstable. Any tool fetched by tag during the build
**will break** when that tag advances past a compatibility boundary:

```dockerfile
# Fragile — breaks when corepack resolves @latest to a version that drops
# support for your Node major version.
RUN corepack enable && corepack prepare pnpm@latest --activate

# Stable — pin to a specific version.
RUN corepack enable && corepack prepare pnpm@10.33.4 --activate
```

The same applies to:
- `npm install -g <tool>@latest`
- `apt-get install <package>` without version pinning on rolling distros
- Base image tags like `node:20` (use the sha256 digest in reproducible
  pipelines, or at minimum `node:20-bookworm-slim` over `node:20-alpine`
  to avoid musl/glibc surprises — see [Class 1 failures](#class-1-rollupmusl-build-failure))

Check your lockfile's version and match it. If your lockfile was generated
with pnpm 9 or 10, pin to that major. If you're on pnpm 10, the latest
10.x is safe.

> **Minimum-age policy.** Some organisations require that externally
> fetched packages are at least 30 days old before production use. The
> rationale: a newly published package version is at higher risk of
> containing an undiscovered vulnerability or supply-chain compromise, and
> the 30-day window gives the community and security scanners time to catch
> problems before they reach production. If this policy applies to you,
> consult the registry publication date of any version you pin — don't
> pin to something released in the last 30 days just because it is the
> latest. In practice this means keeping your `pnpm@X.Y.Z` and
> `node:20-bookworm-slim` pins slightly behind the absolute leading edge.

### The `pnpm prune --prod` boundary

Multi-stage prod images typically strip dev deps to reduce size. This is
correct — but it means anything your container entrypoint **calls** at
runtime must be a regular dependency, not a devDependency.

Common miss: the `prisma` CLI. You run `prisma migrate deploy` at startup.
If `prisma` is in `devDependencies`, it vanishes after `pnpm prune --prod`
and the container crash-loops with a misleading
`Command "prisma" not found` error.

**Rule:** before shipping a prod image, audit your compose `command:` and
entrypoint scripts against the output of `pnpm prune --prod`. Every binary
referenced there must be in `dependencies`.

### Node / libc mismatch (Rollup and friends)

npm has a known issue ([npm/cli#4828](https://github.com/npm/cli/issues/4828)):
when you run `npm ci` or `npm install` in a Linux container, optional
per-platform dependencies (like Rollup's native bindings) may not be
installed if the lockfile was generated on a different platform (e.g. macOS).

Symptoms: the build works locally; Dokploy's build fails during `vite
build` with `Cannot find module @rollup/rollup-linux-x64-musl` (or the
equivalent for your libc/arch).

Fix: switch the build-stage base from `node:20-alpine` to
`node:20-bookworm-slim` and copy only `package.json` — not the lockfile —
into the build stage so npm resolves fresh for the build platform:

```dockerfile
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY frontend/package.json ./        # no lockfile
RUN npm install --no-audit --no-fund
COPY frontend/ .
RUN npm run build
```

The final prod stage can still be `nginx:alpine` — the image size penalty
only affects the intermediate build stage.

---

## The four classes of build failure

### Class 1 — Rollup / musl native-binding failure

**Symptom:** `vite build` fails with
`Cannot find module @rollup/rollup-linux-x64-musl`.

**Root cause:** npm lockfile generated on macOS; `npm ci` skips
installing the Linux native binding because it was never in the lockfile.

**Fix:** glibc base + lockfile-free npm install (see above).

### Class 2 — Package manager drops your Node version

**Symptom:** `corepack prepare pnpm@latest` succeeds, then `pnpm install`
fails with `Error: No such built-in module: node:sqlite`.

**Root cause:** the package manager's `@latest` tag advanced to a version
that requires a newer Node than your image provides.

**Fix:** pin to a specific version (e.g. `pnpm@10.33.4`). Check the
package manager's changelog for "minimum Node version" entries when
bumping.

### Class 3 — CLI stripped by `pnpm prune --prod`

**Symptom:** container starts with the correct image, then crash-loops
with `Command "foo" not found`, where `foo` is a binary your entrypoint
calls.

**Root cause:** `pnpm prune --prod` ran in the build stage and removed the
package that owns that binary (because it was a devDependency).

**Fix:** move the package to `dependencies`. For the Prisma CLI specifically,
this is the documented approach for production deployments.

### Class 4 — Frontend call sites that bypass the apiFetch helper

**Symptom:** a download button saves a 0.5 kB HTML file instead of a
binary; an upload form shows "Failed to fetch".

**Root cause:** the frontend has raw `fetch("/<path>")` calls or
`<a href="/<path>">` anchors that use the old route prefix. The Vite dev
server only proxies an explicit list of prefixes; any path not in that
list falls through to the SPA's `try_files` fallback and the client
receives `index.html` instead of the API response. In production nginx the
same request returns 405 or closes the connection.

**Fix:** after any route-prefix refactor, grep the frontend for call sites
that bypass your fetch helper:

```bash
grep -rn 'fetch("/' src/
grep -rn 'a\.href\s*=\s*"/' src/
grep -rn 'window\.location\s*=\s*"/' src/
```

Update these manually — the helper's path normalisation does not cover
them.

---

## Operator runbook

### First boot: bootstrap admin password

Most web apps create an initial admin account on first boot and print the
password to stdout. This is the only time it is printed. Capture it
immediately:

```bash
docker logs <app>-backend-1 2>&1 | grep -iE 'bootstrap|admin password'
```

If the log has rolled by the time you check, use your app's CLI tool to
regenerate it:

```bash
docker exec <app>-backend-1 node dist/cli/bootstrap-admin.js --email admin@example.com
```

### Rotating a database password

PostgreSQL bakes the password into the data volume on first `docker compose
up`. If you change `POSTGRES_PASSWORD` in the Dokploy env editor and
redeploy, the new backend will fail authentication — the database still
expects the old password.

The safe rotation sequence (on an **empty or already-backed-up** database):

1. **Stop** the stack in the Dokploy UI (this stops containers but does
   not remove them).
2. **Force-remove** the stopped postgres container — Dokploy's Stop leaves
   the container record, which still holds a reference to the volume:
   ```bash
   docker rm -f <app>-postgres-1
   ```
3. **Wipe the data volume** (you just confirmed the database is backed up):
   ```bash
   docker volume rm <app>_pgdata
   ```
4. **Update** `POSTGRES_PASSWORD` (and `DATABASE_URL` if you pass it
   separately) in the Dokploy env editor.
5. **Deploy.** Postgres re-initialises with the new password.

> `docker volume rm` refuses with "volume is in use" if any container
> (running **or stopped**) references it. That is why step 2 — a full
> `docker rm`, not just `docker stop` — is required.

### Redeploying after a code push

Dokploy auto-deploys on webhook (configurable) or via the Deploy button.
Each deploy:
1. Pulls the latest commit.
2. Builds the image from scratch (no layer cache by default on Dokploy
   Community; cached on Enterprise).
3. Runs `docker compose up -d --build --remove-orphans`.

Volumes survive unless you explicitly run `docker compose down -v`.

### DNS cache invalidation after a redeploy

A brief redeploy takes the stack down. On macOS, `mDNSResponder` may cache
a negative answer for your split-horizon hostname during the downtime
window. After the stack comes back up, the browser still can't reach it.

Flush:
```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

Then **fully quit the browser** (Cmd-Q), not just close the tab. Browsers
maintain their own in-process DNS cache that persists across tab cycles.

As an alternative for local testing, add a hard-coded override to
`/etc/hosts`:
```
<dokploy-host-ip>  your-app.example.com
```

Remove it once the DNS record is stable.

### Restoring a database backup

If your app exposes a `/admin/db/restore` endpoint (or equivalent), call
it directly with curl rather than through the UI during troubleshooting —
the browser's cookie handling and multipart encoding add variables:

```bash
# 1. Authenticate
curl -c cookies.txt -X POST https://your-app.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"<password>"}'

# 2. Upload the backup tarball
curl -b cookies.txt -X POST https://your-app.example.com/api/admin/db/restore \
  -F "file=@/path/to/backup.tar.gz"
```

---

## Pre-deploy checklist

Run through this before the first Dokploy deploy and after any major
Dockerfile or Compose change.

**Compose**
- [ ] Compose file path is correct in Dokploy UI.
- [ ] Routing model chosen: **Option A** (publish a host port, access via
      `http://<host>:<port>`, recommended for internal tools) **or Option B**
      (Traefik hostname routing — no `ports:` block, hostname configured in
      Dokploy Domains UI). Not both for the same service.
- [ ] `build.target: prod` is set on every service with a multi-stage
      Dockerfile.
- [ ] Database and cache services have `healthcheck:` blocks and dependent
      services use `condition: service_healthy`.
- [ ] Named volumes declared for all persistent state.
- [ ] `DATABASE_URL` (or equivalent) contains no URL-reserved characters
      in the password. Generate a URL-safe password or pass `DATABASE_URL`
      directly, pre-encoded.

**Dockerfiles**
- [ ] All externally-fetched tools (package managers, global CLIs) are
      pinned to an explicit version, not `@latest`.
- [ ] Node base image is `bookworm-slim` (glibc) if you use Vite or any
      other tool with platform-native npm optional deps.
- [ ] Build stages that run `npm install` without a lockfile (the
      glibc/Rollup workaround) copy only `package.json`, not
      `package-lock.json` / `pnpm-lock.yaml`.
- [ ] Every binary called by the compose `command:` or entrypoint is in
      `dependencies`, not `devDependencies` — and therefore survives
      `pnpm prune --prod`.

**Frontend**
- [ ] After any route-prefix refactor, grepped the frontend for raw
      `fetch("/`, `a.href = "/`, `window.location = "/` call sites and
      updated them.
- [ ] Vite dev proxy list (`vite.config.ts` `proxied`) includes every
      prefix the frontend fetches from the backend.

**Environment**
- [ ] All required env vars documented in `.env.example` are set in the
      Dokploy env editor.
- [ ] `SESSION_COOKIE_SECURE` is `true` if serving over HTTPS; `false` for
      plain HTTP (Option A / internal tools over VPN).
- [ ] `APP_ORIGIN` matches the URL users will actually open (e.g.
      `http://10.0.0.0:8080` for Option A, or
      `https://your-app.example.com` for Option B). Required for CORS.

**First boot**
- [ ] On first deploy, capture the bootstrap admin password from container
      logs before they roll.
- [ ] After bootstrap, immediately test login and verify version/schema
      endpoints return expected values:
      ```bash
      curl https://your-app.example.com/healthz
      curl https://your-app.example.com/version
      ```

---

## See also

- `docs/OPERATIONS.md` — app-specific runbook (backup schedule, log
  locations, alert thresholds).
- `docker/compose/docker-compose.prod.yml` — the production compose file
  this guide was derived from.
- `docker/backend.Dockerfile` / `docker/frontend.Dockerfile` — annotated
  examples of the multi-stage patterns described above.
