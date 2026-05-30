# syntax=docker/dockerfile:1.6
#
# Frontend image for SASTBot.
#
# Stages:
#   dev   - Vite dev server with HMR. Mount the repo as a volume for live reload.
#   build - Produces the static bundle (consumed by the prod stage).
#   prod  - Nginx serving /dist.
#
# Usage (dev):
#   docker compose build frontend
#   docker compose up frontend
#
# Compose reference (example):
#   frontend:
#     build:
#       context: ../../
#       dockerfile: docker/frontend.Dockerfile
#       target: dev
#     ports: ["5173:5173"]
#     environment:
#       BACKEND_URL: http://backend:8000
#     volumes:
#       - ../../frontend:/app
#       - /app/node_modules

############################
# Base: node + pnpm-free npm
############################
# glibc (bookworm-slim) on purpose — alpine/musl breaks Rollup. When `npm ci`
# runs against a package-lock.json generated on a developer's macOS laptop,
# the `@rollup/rollup-linux-x64-musl` optional dep is NOT pinned, so Vite's
# production build (`tsc -b && vite build`) crashes with
# "Cannot find module @rollup/rollup-linux-x64-musl" (npm bug
# https://github.com/npm/cli/issues/4828). The glibc-x64 variant IS in the
# lockfile and works. Image is ~100MB larger but only affects the build
# stage — the prod stage is still nginx:alpine.
# TODO: pin to a specific digest or dated tag at release (e.g. node:20.19.0-bookworm-slim)
FROM node:20-bookworm-slim AS base
WORKDIR /app
ENV CI=1

############################
# Dev
############################
FROM base AS dev
COPY frontend/package.json frontend/package-lock.json* ./
# package-lock.json may not exist yet on a fresh checkout.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ .
# Canonical user-manual content lives at <repo>/docs/user-manual. The `predev`
# sync (scripts/sync-manual.mjs) resolves it at /docs/user-manual (= /app/../../docs/user-manual).
# Compose also bind-mounts it here so live edits are picked up; this COPY makes
# the image self-contained if run without the mount.
COPY docs/user-manual /docs/user-manual
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]

############################
# Build
############################
FROM base AS build
# Copy package.json only — intentionally NOT the lockfile. npm bug
# https://github.com/npm/cli/issues/4828: optional deps for the build
# platform's libc/arch aren't included in a lockfile generated on a
# different platform. Rollup ships its native bindings as such optional
# deps (linux-x64-gnu, linux-arm64-gnu, ...). With the macOS-generated
# lockfile present, both `npm ci` AND `npm install` honour it strictly
# and leave the Linux binding uninstalled, then `vite build` crashes
# with "Cannot find module @rollup/rollup-<arch>-<libc>".
# Letting npm resolve afresh inside the container picks the right
# optional dep for the current platform. We accept the loss of
# lockfile-driven determinism here because the alternative (build
# failure) is worse.
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ .
# User-manual source-of-truth. `prebuild` (scripts/sync-manual.mjs) copies it
# into src/manual/ before `vite build` so it's bundled into the SPA. Resolves at
# /docs/user-manual (= /app/../../docs/user-manual). Build context is the repo root.
COPY docs/user-manual /docs/user-manual
RUN npm run build

############################
# Prod (nginx serves /dist + reverse-proxies /api/* to backend)
############################
# TODO: pin to a specific patch tag at release (e.g. nginx:1.27.4-alpine); verify tag exists first
FROM nginx:1.27-alpine AS prod
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/nginx.prod.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
