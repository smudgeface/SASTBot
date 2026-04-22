"""Run TypeScript type-check on both backend and frontend.

Runs inside the running docker compose services so Node + pnpm versions
match what CI will build against. Assumes the stack is up via::

    docker compose -f docker/compose/docker-compose.yml up -d

Usage::

    python -m scripts.typecheck
"""

from __future__ import annotations

import sys

from ._console import error, run_cmd, section


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
        with section("backend: pnpm typecheck"):
            _compose_exec("backend", ["pnpm", "typecheck"])
        with section("frontend: tsc --noEmit"):
            _compose_exec("frontend", ["npm", "run", "typecheck"])
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
