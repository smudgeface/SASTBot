"""Run unit tests on backend and frontend.

Usage::

    python -m scripts.test
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
        with section("backend: pnpm test (vitest)"):
            _compose_exec("backend", ["pnpm", "test"])
        with section("frontend: npm test (vitest)"):
            _compose_exec("frontend", ["npm", "test"])
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
