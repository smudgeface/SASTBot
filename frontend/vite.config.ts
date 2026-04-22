import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Proxy backend routes to the backend service. When running inside docker-compose
// the backend host is resolvable as `backend`; when running locally without
// docker set BACKEND_URL=http://localhost:8000.
const BACKEND_URL = process.env.BACKEND_URL ?? "http://backend:8000";

const proxied = ["/auth", "/admin", "/scans", "/healthz", "/openapi.json", "/docs", "/api"];

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
