# SASTBot Frontend

React 18 + Vite 5 + TypeScript + Tailwind + shadcn/ui. State is split between
TanStack Query (server) and Zustand (auth snapshot + theme).

## Run locally (without Docker)

```bash
cd frontend
npm install

# Start the backend first (see ../backend/README), then:
BACKEND_URL=http://localhost:8000 npm run dev
```

The dev server listens on `http://localhost:5173` and proxies the backend
routes (`/auth`, `/admin`, `/scans`, `/healthz`, `/openapi.json`, `/docs`,
`/api`) to `$BACKEND_URL` (defaults to `http://backend:8000` for the Docker
setup).

## Scripts

| Script              | Description                                    |
| ------------------- | ---------------------------------------------- |
| `npm run dev`       | Vite dev server (HMR)                          |
| `npm run build`     | `tsc -b && vite build`                         |
| `npm run preview`   | Preview the production build                   |
| `npm run test`      | Run vitest once                                |
| `npm run test:watch`| Watch mode                                     |
| `npm run lint`      | ESLint over `src/**/*.{ts,tsx}`                |
| `npm run typecheck` | `tsc --noEmit`                                 |
| `npm run gen:types` | Regenerate `src/api/schema.d.ts` from backend  |

## Regenerating types

Start the backend, then:

```bash
npm run gen:types
```

This overwrites `src/api/schema.d.ts` with types derived from the live
`/openapi.json`. The file is committed; re-run after backend API changes.

## Structure

```
src/
  api/
    client.ts          # fetch wrapper + ApiError
    schema.d.ts        # generated types (stubbed until first run)
    types.ts           # hand-maintained typed models used by the UI
    queries/           # TanStack Query hooks per-resource
  components/
    ui/                # shadcn primitives
    AppShell.tsx       # sidebar + layout
    RequireAuth.tsx    # auth gate (redirects to /login)
    RequireAdmin.tsx   # admin gate (shows 403 card)
  lib/                 # utils + formatting helpers
  routes/              # page components (App.tsx wires them up)
  stores/              # Zustand stores (auth mirror, theme)
```
