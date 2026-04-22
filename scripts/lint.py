"""Run linters on backend and frontend inside compose services.

Usage::

    python -m scripts.lint
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
        with section("backend: pnpm lint"):
            _compose_exec("backend", ["pnpm", "lint"])
        with section("frontend: npm run lint"):
            _compose_exec("frontend", ["npm", "run", "lint"])
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
