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
FROM node:20-alpine AS base
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
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]

############################
# Build
############################
FROM base AS build
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ .
RUN npm run build

############################
# Prod (nginx serves /dist)
############################
FROM nginx:1.27-alpine AS prod
COPY --from=build /app/dist /usr/share/nginx/html
# A minimal SPA-friendly default config.
RUN printf 'server {\n\
  listen 80;\n\
  root /usr/share/nginx/html;\n\
  index index.html;\n\
  location / {\n\
    try_files $uri /index.html;\n\
  }\n\
}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
