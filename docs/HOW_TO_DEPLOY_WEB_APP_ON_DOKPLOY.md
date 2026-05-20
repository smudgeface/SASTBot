# Deploying a Compose-based web app to Dokploy

A practical guide for engineers deploying an app to a self-hosted Dokploy
instance for the first time. Assumes Docker Compose familiarity; does not
assume Dokploy familiarity.

---

## Mental model

Dokploy wraps `docker compose` with a deployment UI that:

- Pulls your git repo on every deploy trigger.
- Runs `docker compose up -d --build --remove-orphans`.
- Fronts every stack with **Traefik**, which can route traffic by hostname
  and terminate TLS — but you can bypass Traefik for internal tools (see below).
- Injects env vars from its own database. **There is no `.env` file on the
  deploy host.** Your `.env.example` documents what is needed; the Dokploy
  env editor is where values are set.

---

## Routing model — choose one

### Option A: direct IP:port (recommended for internal tools)

Publish a host port on your web server container. Users access the app at
`http://<dokploy-host-ip>:<port>` directly — no hostname, no DNS, no TLS
required. Right for tools only ever reached over VPN or a corporate LAN.

```yaml
services:
  web:
    ports:
      - "8080:80"   # pick a port unique to this stack on the host
```

### Option B: Traefik + hostname routing

Omit the `ports:` block. Configure the hostname in the Dokploy Domains UI;
Traefik routes by `Host:` header and can provision a TLS cert via Let's
Encrypt (requires externally-resolvable DNS).

```yaml
services:
  web:
    expose:
      - "80"
    # no ports:
```

Don't use both for the same service — you get two entry points at
different URLs.

---

## Structuring your Compose file

### Compose file location

Set the compose file path in the Dokploy UI under Application settings.
Keep it in a subdirectory (e.g. `docker/compose/docker-compose.prod.yml`)
rather than at the repo root so local dev invocations don't pick it up.

### Build target

If your Dockerfile uses multi-stage builds, specify the production target
explicitly:

```yaml
services:
  backend:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: prod
```

Without `target:`, Docker builds the last stage — often your dev stage.

### Healthchecks and startup order

If services depend on each other being ready (e.g. an API waiting for a
database), use healthchecks and condition-based `depends_on`:

```yaml
services:
  api:
    depends_on:
      db:
        condition: service_healthy

  db:
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$DB_USER"]
      interval: 5s
      retries: 10
      start_period: 10s
```

`$$` escapes the `$` from Compose interpolation so the shell sees one `$`.

### Named volumes

Declare named volumes for any state that must survive a redeploy:

```yaml
volumes:
  db_data:
  file_storage:
```

Dokploy does **not** delete volumes on redeploy — only `docker compose down -v`
does. This is the right default.

### URL-safe secrets in connection strings

If you build a connection URL from individual env vars (e.g.
`postgresql://${DB_USER}:${DB_PASSWORD}@db:5432/${DB_NAME}`), Compose does
no percent-encoding. Any URL-reserved character in a variable — `/`, `@`,
`:`, `?`, `#`, `&`, `%` — silently corrupts the URL at substitution time
and causes cryptic parse errors downstream.

Options:
1. Restrict generated secrets to alphanumerics + `_-.~`.
2. Accept the full connection string as a single env var and have the
   operator set it with the password already percent-encoded.

---

## Structuring your Dockerfiles

### Multi-stage builds

Use separate stages for building and running. Only the final stage ships
to production; intermediate stages can carry compilers, test runners, and
dev tooling that you don't want at runtime.

### Pin every externally-fetched tool

`docker build` hits the registry as it is at build time. Anything fetched
by a floating tag (`@latest`, `stable`, a major-only semver like `v3`)
will eventually advance past a compatibility boundary and break your build.

```dockerfile
# Fragile
RUN corepack prepare pnpm@latest --activate

# Stable
RUN corepack prepare pnpm@10.33.4 --activate
```

The same applies to global npm installs, `apt-get` packages on rolling
distros, and base image tags. Pin to an explicit version and update
deliberately.

> **Minimum-age policy.** Some organisations require that externally
> fetched package versions are at least 30 days old before use in
> production — the window gives the community and security scanners time to
> catch supply-chain or vulnerability issues in newly published releases.
> If this policy applies to you, check the publication date of any version
> you pin and don't chase the absolute latest.

### Runtime vs. build-time dependencies

Some build tools include a "prune dev dependencies" step to slim the final
image. If your container's startup command calls a CLI that was only
installed as a dev dependency, it will be missing at runtime and the
container will crash-loop.

Audit your `command:` and any entrypoint scripts: every binary they invoke
must survive the prune step. Move it to regular dependencies if it doesn't.

---

## Pre-deploy checklist

**Compose**
- [ ] Compose file path set correctly in Dokploy UI.
- [ ] Routing model chosen: Option A (host port) or Option B (Traefik,
      no `ports:` block). Not both for the same service.
- [ ] `build.target: prod` set on every service with a multi-stage Dockerfile.
- [ ] Services that depend on other services being ready use
      `condition: service_healthy`.
- [ ] Named volumes declared for all persistent state.
- [ ] Connection strings containing secrets use only URL-safe characters,
      or are passed as a single pre-encoded env var.

**Dockerfiles**
- [ ] All externally-fetched tools pinned to an explicit version.
- [ ] Every binary called by `command:` or entrypoint scripts survives the
      dev-dependency prune step.

**Environment**
- [ ] All required env vars (from `.env.example`) set in Dokploy env editor.
- [ ] `SESSION_COOKIE_SECURE=false` if serving over plain HTTP (Option A).
- [ ] CORS origin env var matches the URL users will actually open.

**First boot**
- [ ] Any first-boot initialisation (generated secrets, seed data, initial
      admin account) is captured from container logs before they roll.
- [ ] Health and version endpoints return expected responses
