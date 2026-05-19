// vitest/config re-exports vite's defineConfig with vitest's options merged
// in, so the `test:` block at the bottom is type-checked. Importing from
// `vite` directly would type-error on `test` under `tsc -b` (the prod build).
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Proxy backend routes to the backend service. When running inside docker-compose
// the backend host is resolvable as `backend`; when running locally without
// docker set BACKEND_URL=http://localhost:8000.
const BACKEND_URL = process.env.BACKEND_URL ?? "http://backend:8000";

// Post-M-deploy (0.2.0): all domain routes live under /api/*. The list still
// includes /healthz, /version, /openapi.json, and /docs since those stay at
// root in the backend (monitoring + Swagger conventions).
const proxied = ["/api", "/healthz", "/version", "/openapi.json", "/docs"];

// Vite's proxy matches on path only — but the React app uses some of these
// paths (e.g. /admin/repos) for client-side routes. If the user reloads or
// deep-links, the browser requests HTML, and without this bypass Vite would
// forward the request to the backend and render raw JSON.
// Return the original URL from `bypass` → Vite serves index.html and the
// SPA router takes over.
function htmlBypass(req: { headers: { accept?: string }; url?: string }) {
  if (req.headers.accept?.includes("text/html")) return req.url;
  return undefined;
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    watch: {
      // Docker Desktop bind mounts on macOS don't emit inotify events.
      usePolling: true,
      interval: 300,
    },
    proxy: Object.fromEntries(
      proxied.map((p) => [
        p,
        { target: BACKEND_URL, changeOrigin: true, secure: false, bypass: htmlBypass },
      ]),
    ),
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: false,
  },
});
