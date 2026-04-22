# SASTBot build scripts

Modern Python 3 build and CI entry points. Standard library only — no
`pip install` required before running any of these.

Run from the **repo root** as modules:

```bash
python -m scripts.ci            # full CI: typecheck → lint → test → openapi-drift → build
python -m scripts.typecheck
python -m scripts.lint
python -m scripts.test
python -m scripts.check_openapi
python -m scripts.build_images
python -m scripts.deploy
```

Every script returns **exit code 0** on success and non-zero on failure,
and prints a coloured section header with timing. Set `NO_COLOR=1` to
disable ANSI escapes.

## Scripts

| Script | Purpose |
|--------|---------|
| `ci.py` | Umbrella runner. Orchestrates all the others; fails fast. |
| `typecheck.py` | `pnpm typecheck` (backend) + `tsc --noEmit` (frontend). |
| `lint.py` | `pnpm lint` (backend) + `npm run lint` (frontend). |
| `test.py` | `pnpm test` (backend vitest) + `npm test` (frontend vitest). |
| `check_openapi.py` | Generates fresh types from the running backend's `/openapi.json` and diffs against the committed `frontend/src/api/schema.d.ts`. Fails on drift. |
| `build_images.py` | Builds the backend and frontend Docker images. Supports `--tag`, `--only`, `--target {dev,prod}`. |
| `deploy.py` | POSTs the Dokploy webhook defined by `DOKPLOY_WEBHOOK_URL`. No homelab specifics baked in. |

## Pre-requisites

- Python 3.9+
- Docker + Docker Compose v2 (for test, typecheck, lint, check_openapi — all run against the live compose stack so Node versions match)
- The compose stack brought up with `docker compose -f docker/compose/docker-compose.yml up -d`

For `build_images.py` alone you only need Docker — no compose stack required.

For `deploy.py` set:

```bash
export DOKPLOY_WEBHOOK_URL="http://<dokploy-host>:3000/api/deploy/compose/<webhook-id>"
export DOKPLOY_REF="refs/heads/main"           # optional, default shown
export DOKPLOY_REPO_FULL="smudgeface/SASTBot"  # optional, default shown
```

The webhook URL is sensitive (contains a secret). Don't commit it.
Homelab-specific values live in `docs/DEPLOY_HOMELAB.md` which is
gitignored.

## Writing a new script

```python
"""One-line purpose.

Longer explanation, usage, env vars, …
"""

from __future__ import annotations

import sys

from ._console import error, run_cmd, section


def run() -> int:
    try:
        with section("step 1"):
            run_cmd(["echo", "hello"])
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
```

Conventions:

- Export a zero-arg (or argv-taking) `run()` that returns an `int`.
- Put a `if __name__ == "__main__": sys.exit(run())` guard at the bottom.
- Import shared helpers from `._console`: `section`, `info`, `warn`, `error`, `success`, `run_cmd`, `repo_root`.
- Use `argparse` for flags; put the parser inside `run()` so tests/callers can pass a custom `argv`.
- Stay on the Python standard library — no pip deps, ever.
