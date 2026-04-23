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

ARG OPENGREP_VERSION=1.20.0

# System tools:
#   openssl, ca-certificates — TLS + Prisma
#   git, openssh-client — the scan worker shells out to `git clone` and
#     drives SSH authentication via GIT_SSH_COMMAND
#   ripgrep — scope-confined grep for reachability analysis
#   curl — used below to fetch the Opengrep binary
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssl ca-certificates git openssh-client ripgrep curl \
 && rm -rf /var/lib/apt/lists/*

# Opengrep SAST binary — manylinux (glibc-compatible), arch-aware.
# uname -m: "x86_64" → manylinux_x86, "aarch64" → manylinux_aarch64.
# Wrapped in || echo so a bad version/network glitch doesn't fail the image build;
# the worker detects a missing binary at runtime and writes a scan warning.
RUN MACHINE=$(uname -m) \
 && OPENGREP_ARCH=$([ "$MACHINE" = "aarch64" ] && echo "manylinux_aarch64" || echo "manylinux_x86") \
 && curl -fsSL \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_${OPENGREP_ARCH}" \
      -o /usr/local/bin/opengrep \
 && chmod +x /usr/local/bin/opengrep \
 || echo "WARN: opengrep install failed — SAST will be unavailable"

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
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend

COPY --from=build /app/backend/package.json /app/backend/pnpm-lock.yaml* ./
COPY --from=build /app/backend/node_modules ./node_modules
COPY --from=build /app/backend/dist ./dist
COPY --from=build /app/backend/prisma ./prisma

EXPOSE 8000

CMD ["node", "dist/server.js"]
