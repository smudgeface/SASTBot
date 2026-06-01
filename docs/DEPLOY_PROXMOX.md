# Deploying SASTBot from pre-built images (manual Docker host / Proxmox)

This runbook is for the operator standing up SASTBot on a **manually-managed
Docker host** — for example a Proxmox VM or LXC — using **pre-built container
images** pulled from a registry. The host never builds from source.

If you instead deploy via Dokploy (which builds the images itself), use
`docker/compose/docker-compose.prod.yml` and the in-app manual's
*Admin → Deployment* page instead.

> **Conventions in this doc.** Anything written `<like-this>` or `REPLACE_ME`
> is a value you supply — the SASTBot maintainer provides the registry/image
> details; you choose the secrets and hostnames. No internal hostnames, IPs, or
> workspace names are baked into the tracked files.

---

## 1. What you are deploying

Five containers, defined in `docker/compose/docker-compose.proxmox.yml`:

| Service | Image | Role | Published? |
|---|---|---|---|
| `postgres` | `postgres:16` | Database | No (internal only) |
| `redis` | `redis:7` | Job queue broker | No (internal only) |
| `backend` | `<registry>/sastbot-backend:<tag>` | API + admin endpoints | No (internal only) |
| `worker` | `<registry>/sastbot-backend:<tag>` (same image) | Runs scans | No (internal only) |
| `frontend` | `<registry>/sastbot-frontend:<tag>` | Nginx: serves the UI **and** reverse-proxies the API | **Yes — HTTP port** |

All browser and API traffic enters through the **frontend** container, which
proxies `/api/*`, `/healthz`, `/version`, `/openapi.json`, and `/docs` to the
backend on the internal network. You only publish one port.

The `backend` and `worker` share one image and differ only by command. On every
start the backend's entrypoint **takes a DB backup, verifies it, rotates old
ones, then runs `prisma migrate deploy`** before the API starts — so upgrades
migrate themselves. The worker skips backup/migrate so it doesn't race the
backend.

---

## 2. Prerequisites on the host

- Docker Engine 24+ and the Docker Compose v2 plugin (`docker compose version`).
- Outbound network access to the container registry.
- A DNS name or stable IP the browser will use to reach the host.
- ~20 GB free disk to start (grows with scan history — see §9).

---

## 3. Get a read-only pull credential

The images live in a private registry. The deploy host needs a **read-only**
credential — **separate** from the CI push credentials. The SASTBot maintainer
creates it; these are the steps they follow (recorded here so the request is
unambiguous):

> **Use an Atlassian API token with scopes — NOT a Bitbucket Access Token.**
> Pulling from `crg.apkg.io` outside Bitbucket Pipelines is only supported with
> an **Atlassian API token** carrying the **`read:package:bitbucket`** scope.
> Repository and workspace *Access Tokens* (the `ATCTT…` kind) **do not work for
> registry pulls** — they have no package scope and the registry rejects them
> with `unauthorized` regardless of username. (Verified empirically + per
> Atlassian docs/community.)

**Create an Atlassian API token with the package-read scope:**

1. Go to **id.atlassian.com → Security → API tokens → Create API token with
   scopes** (the *scoped* token flow, not the plain one).
2. Select the **Bitbucket** app.
3. Grant the **minimum** scope: **`read:package:bitbucket`** only. Do **not**
   add `write:package:bitbucket` or any repository scope.
4. Name it descriptively, e.g. `sastbot-registry-pull`, and copy the token value
   **once** (it is shown only at creation). It looks like `ATATT…`.

> **Personal-account caveat.** An Atlassian API token is tied to the **user
> account** that created it, not to the repo or workspace — there is currently no
> repo/workspace robot credential for registry pull. For an unattended deploy
> host, create the token under a **dedicated service Atlassian account** rather
> than an individual's, so the deploy doesn't break when that person leaves or
> rotates their token.

The maintainer hands you two things:
- the **registry + namespace prefix** (the `SASTBOT_REGISTRY` value, e.g.
  `crg.apkg.io/<workspace>`), and
- the **token** plus the **Atlassian account email** to use as the username.

**Log in on the host** (email is the username, the API token is the password):

```sh
docker login crg.apkg.io
# Username: <the-atlassian-account-email>
# Password: <the read:package:bitbucket API token>
```

This writes `~/.docker/config.json`. Compose reuses that session for `pull`.

---

## 4. Put the compose + env on the host

You need just two files on the host — no source checkout required:

- `docker-compose.proxmox.yml` (from `docker/compose/` in this repo)
- a `.env` you create from `.env.proxmox.example`

Create a working directory and drop them in, e.g.:

```sh
mkdir -p /opt/sastbot && cd /opt/sastbot
# Copy docker-compose.proxmox.yml here (scp, git archive, copy/paste — your choice)
# Copy .env.proxmox.example here as .env
cp .env.proxmox.example .env
```

> Keep the host-specific values (the real `.env`, the hostname/IP, the registry
> namespace) on the host only. Do not commit them back to the repo.

---

## 5. Configure `.env`

Edit `.env`. The fields that **must** change:

| Variable | Set to |
|---|---|
| `SASTBOT_REGISTRY` | The prefix the maintainer gave you, e.g. `crg.apkg.io/<workspace>`. |
| `SASTBOT_IMAGE_TAG` | `latest`, or pin a version like `0.17.0` for repeatability (recommended for prod). |
| `SASTBOT_HTTP_PORT` | The host port to serve on. `80` if free. |
| `MASTER_KEY` | A fresh key: `openssl rand -base64 32`. **Save it in a password manager.** |
| `POSTGRES_PASSWORD` | A strong password. |
| `APP_ORIGIN` | The exact URL users type, scheme included, no trailing slash. A **bare IP is fine — no domain needed**. E.g. `http://sastbot.<your-domain>`, or `http://192.168.20.50:8080` (add `:PORT` unless it's 80). |
| `SESSION_COOKIE_SECURE` | `false` for an HTTP-only deploy (see §8 before setting `true`). |
| `ALLOW_INSECURE_COOKIES` | `true` for an HTTP-only deploy. **Required** to boot with `SESSION_COOKIE_SECURE=false` — the app otherwise refuses to start in production to avoid shipping plaintext-HTTP cookies by accident. Cookies travel in clear text while this is on; only safe on a trusted LAN. Flip to `false` once TLS is in front (§8). |

> **MASTER_KEY is load-bearing and permanent.** It decrypts stored credentials.
> If you lose it or change it after credentials exist, those credentials are
> unrecoverable. Treat it like the root password to a vault.

---

## 6. Pull and start

```sh
cd /opt/sastbot
docker compose -f docker-compose.proxmox.yml --env-file .env pull
docker compose -f docker-compose.proxmox.yml --env-file .env up -d
```

Watch it come up:

```sh
docker compose -f docker-compose.proxmox.yml ps
docker compose -f docker-compose.proxmox.yml logs -f backend
```

On first boot the backend runs migrations and prints a **one-time bootstrap
admin password**. Grab it:

```sh
docker compose -f docker-compose.proxmox.yml logs backend | grep BOOTSTRAP
```

Capture that password — it is printed once. The admin email defaults to
`admin@sastbot.local` (override with `BOOTSTRAP_ADMIN_EMAIL` before first boot).

---

## 7. First-login configuration

1. Browse to `APP_ORIGIN` (e.g. `http://sastbot.<your-domain>`).
2. Log in as the bootstrap admin; change the password.
3. **Configure the LLM** under **Settings → LLM**: base URL, model, and a
   credential. Scans will not run until this is set — the LLM auth is stored
   (encrypted) in the DB and injected into the scan subprocess at run time, so
   there is **no** API-key environment variable to set on the host.

From here follow the in-app manual's Quick Start.

---

## 8. TLS / HTTPS (when you're ready)

This stack publishes **plain HTTP** and ships with `SESSION_COOKIE_SECURE=false`
plus `ALLOW_INSECURE_COOKIES=true` (the explicit acknowledgement the app requires
to run insecure cookies in production). That is fine for an internal-only first
deploy, but **login cookies travel in the clear** — anyone who can sniff the
network segment can hijack a session. Move to HTTPS before exposing SASTBot
beyond a trusted segment.

There is no Traefik/ingress on a manual host, so terminate TLS with a
**host-level reverse proxy** in front of the published frontend port:

1. Pick a host port for the stack that is **not** 80/443, e.g. set
   `SASTBOT_HTTP_PORT=8080`.
2. Install nginx or Caddy **on the host** and proxy `:443` → `127.0.0.1:8080`.
   - Caddy with an internal/corporate CA or a real cert is the least-effort option.
   - Forward the original `Host` header and `X-Forwarded-Proto https`.
3. Set `APP_ORIGIN=https://sastbot.<your-domain>`, `SESSION_COOKIE_SECURE=true`,
   and `ALLOW_INSECURE_COOKIES=false` in `.env`.
4. `docker compose -f docker-compose.proxmox.yml --env-file .env up -d` to apply.

Minimal Caddy example (`/etc/caddy/Caddyfile`):

```
sastbot.<your-domain> {
    reverse_proxy 127.0.0.1:8080
}
```

> The frontend's nginx already proxies `/api/*` and the operational endpoints to
> the backend, so the host proxy only needs the single `reverse_proxy` line —
> don't re-implement the API routing in the host proxy.

---

## 9. Backups & disaster recovery

Two independent layers:

**A. Automatic pre-deploy DB backup (built in).** Every backend start dumps the
DB to the `sastbot_backups` volume, verifies the gzip CRC, and keeps the last
`BACKUP_RETENTION_COUNT` (default 10). Copy one out:

```sh
docker compose -f docker-compose.proxmox.yml exec backend ls -1t /backups
docker compose -f docker-compose.proxmox.yml cp \
  backend:/backups/<file>.tar.gz ./
```

Restore a tarball through the admin UI (**Admin → Backup & restore**) or the
`POST /api/admin/db/restore` endpoint. Restore compares schema versions and will
refuse a dump that is newer than the running app (HTTP 422).

> **Restoring onto a *different* instance? Match the `MASTER_KEY` first.** A full
> backup carries the encryption canary + all credential ciphertexts encrypted
> under the source instance's `MASTER_KEY`. Set this host's `MASTER_KEY` to the
> source value **before** restoring — otherwise the restore is refused (HTTP 422,
> key-fingerprint mismatch), and even if forced the backend would fail its canary
> on next boot. Without the original key, the encrypted data is unrecoverable.

**B. Volume snapshots (recommended for true DR).** The DB backup tarball does
**not** include the artifact files. Snapshot these volumes at the storage layer
(ZFS/LVM/Proxmox backup):

| Volume | Holds | Approx growth |
|---|---|---|
| `sastbot_pgdata` | All findings + scan history | 1–10 GB |
| `sastbot_artifacts` | Per-scan SBOM + SARIF files | 100 MB – few GB |
| `sastbot_repo_cache` | Retained clones (regenerable) | 1–50 GB |
| `sastbot_redisdata` | Job queue (transient) | < 100 MB |
| `sastbot_backups` | Rotated DB dumps | 100 MB – few GB |

`sastbot_pgdata` + `sastbot_artifacts` are the two that matter for recovery.

---

## 10. Upgrading

1. Ask the maintainer for the new tag (e.g. `0.17.0`), or keep `latest`.
2. On the host:

   ```sh
   cd /opt/sastbot
   # If pinning: edit SASTBOT_IMAGE_TAG in .env
   docker compose -f docker-compose.proxmox.yml --env-file .env pull
   docker compose -f docker-compose.proxmox.yml --env-file .env up -d
   ```

3. The backend entrypoint **takes a fresh backup and runs migrations
   automatically** before serving. Verify:

   ```sh
   curl -s http://localhost:${SASTBOT_HTTP_PORT:-80}/version
   ```

   `app` should show the new version and `schema` should equal
   `expected_schema`.

> Pinning `SASTBOT_IMAGE_TAG` to an explicit version is recommended for prod: a
> re-pull can't then silently change what runs, and rollback is "set the old tag
> + `up -d`". With `latest`, a `pull` always fetches the newest build.

**Rollback:** set `SASTBOT_IMAGE_TAG` back to the previous version and `up -d`.
If a migration ran, restore the pre-upgrade backup from `sastbot_backups` first
(forward migrations are not auto-reversed).

---

## 11. Health & monitoring

- `GET /healthz` → `{ status: "ok", version }`. Container liveness (the image
  also has a built-in Docker `HEALTHCHECK` on this).
- `GET /version` → `{ app, schema, expected_schema }`. Deploy-success check; a
  `schema` ≠ `expected_schema` means migrations didn't complete.

```sh
curl -s http://localhost:${SASTBOT_HTTP_PORT:-80}/healthz
curl -s http://localhost:${SASTBOT_HTTP_PORT:-80}/version
```

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `pull` fails with `unauthorized` / `denied` | Wrong credential type, or not logged in. A Bitbucket *Access Token* (`ATCTT…`) does **not** work — registry pulls need an **Atlassian API token** (`ATATT…`) with `read:package:bitbucket` (see §3) | `docker login crg.apkg.io` with the Atlassian account **email** as username and the API token as password |
| `pull` fails with `manifest unknown` / `not found` | Wrong `SASTBOT_REGISTRY` or `SASTBOT_IMAGE_TAG` | Confirm the exact prefix + tag with the maintainer |
| `pull` tries `crg.apkg.io/REPLACE_ME/...` | `SASTBOT_REGISTRY` not set (placeholder default) | Set `SASTBOT_REGISTRY` in `.env`, pass `--env-file .env` |
| Backend exits on boot, logs mention MASTER_KEY / canary | `MASTER_KEY` empty, wrong length, or changed | Set a valid 32-byte base64 key; if changed after credentials existed, restore a backup |
| Backend boot-loops on "Aborting deploy" | Pre-deploy backup failed (disk full / DB down) | Fix the cause; as a last resort set `ALLOW_DEPLOY_WITHOUT_BACKUP=true` once to break the loop, then revert |
| Backend/worker crash-loop: `SESSION_COOKIE_SECURE must be true in production` | Running HTTP-only (`SESSION_COOKIE_SECURE=false`) without the acknowledgement flag | Set `ALLOW_INSECURE_COOKIES=true` (HTTP-only), or set `SESSION_COOKIE_SECURE=true` + finish HTTPS (§8) |
| Login works via API but browser logs out on refresh | `SESSION_COOKIE_SECURE=true` over plain HTTP | Set it `false` (+ `ALLOW_INSECURE_COOKIES=true`), or finish the HTTPS setup in §8 |
| CORS errors in the browser console | `APP_ORIGIN` ≠ the URL actually used (only affects cross-origin API calls — the bundled UI is same-origin) | Set `APP_ORIGIN` to the exact scheme+host+port users type, e.g. `http://192.168.20.50:8080` — a bare IP is fine, no trailing slash |
| Scans never start / fail immediately | LLM not configured | Set **Settings → LLM** (base URL, model, credential) |
| SARIF/SBOM downloads 404 | backend/worker `ARTIFACT_DIR` or volume mismatch | Both must mount `sastbot_artifacts` at `/var/lib/sastbot/artifacts` (the compose does this — don't override) |
| Worker can't decrypt credentials | Different `MASTER_KEY` on backend vs worker | They share one `.env`; ensure you didn't override it per-service |
| Restore refused: `different MASTER_KEY than this instance` (422) | Restoring a backup taken under a different key | Set `MASTER_KEY` to the source instance's value, restart, then retry — see §9 |
| Port 80 already in use | Another service owns it | Set `SASTBOT_HTTP_PORT` to a free port and update `APP_ORIGIN` |

---

For the architecture deep-dive, versioning policy, and the in-app admin
manual, see `CLAUDE.md` and the in-app **Manual** (the *Admin* group).
