# syntax=docker/dockerfile:1.7
# SASTBot backend image — Node.js 20 + pnpm + Prisma.
#
# Shared by the `backend` (HTTP API) and `worker` (BullMQ) compose services;
# they only differ by the `command` override at runtime.
#
# Build from repo root:
#   docker build -f docker/backend.Dockerfile --target dev  -t sastbot-backend:dev  .
#   docker build -f docker/backend.Dockerfile --target prod -t sastbot-backend:prod .

# ---------- base ----------
FROM node:20-bookworm-slim AS base

ENV NODE_ENV=development \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=1

# Enable pnpm via corepack.
RUN corepack enable && corepack prepare pnpm@latest --activate

# System tools:
#   openssl, ca-certificates — TLS + Prisma
#   git, openssh-client — the scan worker shells out to `git clone` and
#     drives SSH authentication via GIT_SSH_COMMAND
#   ripgrep — used by the LLM agent for fast scope-confined grep
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssl ca-certificates git openssh-client ripgrep \
 && rm -rf /var/lib/apt/lists/*

# Claude Code CLI — drives the SAST + reachability + vendored-lib pass.
# Auth via env vars (ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL) injected by the
# worker per-scan from AppSettings.
RUN npm install -g @anthropic-ai/claude-code \
 || echo "WARN: claude-code install failed — SAST will be unavailable"

# claude-p refuses --dangerously-skip-permissions (its mapping for our chosen
# permission-mode) when the calling process is root. Add a dedicated unprivileged
# user the worker process drops to when spawning claude. The worker itself stays
# root for the rest of its work (npm, prisma, /app file writes).
RUN useradd --create-home --uid 1001 --shell /bin/bash claudeuser

WORKDIR /app/backend

# Copy manifest + Prisma schema first so the install layer is cached.
COPY backend/package.json backend/pnpm-lock.yaml* ./
COPY backend/prisma ./prisma

# Install dependencies (production + dev for build/typecheck). Prisma's
# postinstall hook will generate the client using the copied schema.
RUN pnpm install --frozen-lockfile || pnpm install

# Copy the rest of the source.
COPY backend/ ./

# Make sure the client is generated against the schema we have.
RUN pnpm prisma generate

EXPOSE 8000

# ---------- dev ----------
# `tsx watch` gives us reloads in development. Compose bind-mounts the
# backend/ directory so host-side edits reach the running process.
FROM base AS dev

ENV NODE_ENV=development

CMD ["pnpm", "dev"]

# ---------- build ----------
FROM base AS build

ENV NODE_ENV=production

RUN pnpm build

# Trim dev dependencies for the prod layer below.
RUN pnpm prune --prod

# ---------- prod ----------
# Plain `node` runs the compiled JS. `prisma migrate deploy` is invoked by
# the compose `command:` override (backend service) or inline entrypoint.
FROM node:20-bookworm-slim AS prod

ENV NODE_ENV=production \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH

RUN corepack enable && corepack prepare pnpm@latest --activate \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates ripgrep \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code \
 || echo "WARN: prod-stage tool install partial failure"

WORKDIR /app/backend

COPY --from=build /app/backend/package.json /app/backend/pnpm-lock.yaml* ./
COPY --from=build /app/backend/node_modules ./node_modules
COPY --from=build /app/backend/dist ./dist
COPY --from=build /app/backend/prisma ./prisma

EXPOSE 8000

CMD ["node", "dist/server.js"]
