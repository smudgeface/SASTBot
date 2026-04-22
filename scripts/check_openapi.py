"""Verify that the frontend's generated OpenAPI types match what the backend serves.

The committed ``frontend/src/api/schema.d.ts`` is the contract the frontend was
built against. If the backend drifts (route added, request shape changed) and
someone forgets to run ``npm run gen:types`` + commit the diff, this script
fails the build. Direct lesson from the M1 QA pass.

Usage::

    python -m scripts.check_openapi

Requires the backend service to be running on http://localhost:8000 (via
compose), and ``node`` + ``openapi-typescript`` available inside the frontend
container.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

from ._console import error, info, run_cmd, section


BACKEND_OPENAPI = "http://localhost:8000/openapi.json"
COMMITTED_SCHEMA = "frontend/src/api/schema.d.ts"
GENERATED_SCHEMA = "frontend/src/api/schema.generated.d.ts"


def _backend_reachable() -> bool:
    try:
        with urllib.request.urlopen(BACKEND_OPENAPI, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def _compose_exec(service: str, args: list[str]) -> None:
    run_cmd(
        [
            "docker",
            "compose",
            "-f",
            "docker/compose/docker-compose.yml",
            "--env-file",
            ".env",
            "exec",
            "-T",
            service,
        ]
        + args,
    )


def run() -> int:
    try:
        with section("preflight: backend reachable"):
            if not _backend_reachable():
                error(
                    f"Cannot reach {BACKEND_OPENAPI}. "
                    "Start the stack with 'docker compose -f docker/compose/docker-compose.yml up -d'."
                )
                return 1
            info("backend is serving /openapi.json")

        with section("generate fresh types from live backend"):
            # The frontend container has `openapi-typescript` as a dev dep.
            # We write to schema.generated.d.ts so we can diff without touching
            # the committed file.
            _compose_exec(
                "frontend",
                [
                    "npx",
                    "openapi-typescript",
                    "http://backend:8000/openapi.json",
                    "-o",
                    f"/app/src/api/schema.generated.d.ts",
                ],
            )

        with section("diff generated vs committed schema"):
            # Host-side diff because the bind mount reflects the file the
            # container just wrote.
            result = run_cmd(
                ["diff", "-u", COMMITTED_SCHEMA, GENERATED_SCHEMA],
                check=False,
            )
            if result.returncode == 0:
                info("types are in sync")
                # Clean up the generated sibling file.
                run_cmd(["rm", "-f", GENERATED_SCHEMA], check=False)
                return 0
            error(
                "OpenAPI types drift detected.\n"
                f"  Run: (cd frontend && npm run gen:types) and commit the change to {COMMITTED_SCHEMA}."
            )
            return 1
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(run())
