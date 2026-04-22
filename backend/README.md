# SASTBot backend

Node.js 20 + TypeScript 5 + Fastify + Prisma + BullMQ. This is the M1 walking
skeleton: auth (local, DB-backed sessions), repo/credential/settings CRUD, and a
stub scan worker.

The authoritative run-everything path is `docker compose` from the project
root (see top-level `CLAUDE.md`). What follows is the outside-Docker dev flow.

## Prereqs

- Node.js >= 20
- pnpm (`corepack enable && corepack prepare pnpm@latest --activate`)
- A Postgres 16 and a Redis reachable from your shell

## Install + migrate

```bash
pnpm install
pnpm prisma generate
pnpm prisma migrate deploy   # or `migrate dev` to create one on first run
```

## Environment

Copy `.env.example` to `.env` and fill it in. At minimum:

```bash
MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
DATABASE_URL=postgresql://sastbot:sastbot@localhost:5432/sastbot
REDIS_URL=redis://localhost:6379/0
APP_ORIGIN=http://localhost:5173
SESSION_COOKIE_SECURE=false
```

The server refuses to boot if `MASTER_KEY` is missing, not 32 bytes, or doesn't
match the `encryption_canary` row in the database.

## Run

```bash
pnpm dev          # Fastify server (hot reload via tsx watch)
pnpm worker       # BullMQ worker (stub scan jobs)
```

Then:
- API: <http://localhost:8000>
- OpenAPI docs: <http://localhost:8000/docs>
- OpenAPI JSON: <http://localhost:8000/docs/json>

On first boot you'll see a line like:

```
[BOOTSTRAP] admin email: admin@sastbot.local password: <generated>
```

Log in at the frontend once and rotate the password.

## Tests / typecheck / lint

```bash
pnpm typecheck
pnpm lint
pnpm test
```

The M1 test suite covers pure functions (AES-GCM round-trip, bcrypt,
config validation). DB-backed integration tests are deferred until a
testcontainers setup lands.

## Create an admin manually

```bash
pnpm bootstrap-admin --email you@example.com
```

Prints a random password to stdout.
