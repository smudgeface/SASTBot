"""Build the backend and frontend Docker images (prod targets).

Usage::

    python -m scripts.build_images
    python -m scripts.build_images --tag mytag      # override tag, default 'latest'
    python -m scripts.build_images --only backend   # build just the backend
"""

from __future__ import annotations

import argparse
import sys

from ._console import error, run_cmd, section


def _docker_build(dockerfile: str, tag: str, target: str) -> None:
    run_cmd(
        [
            "docker",
            "build",
            "-f",
            dockerfile,
            "--target",
            target,
            "-t",
            tag,
            ".",
        ],
    )


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build SASTBot Docker images.")
    parser.add_argument(
        "--tag",
        default="latest",
        help="Tag to apply to the built images (default: latest).",
    )
    parser.add_argument(
        "--only",
        choices=("backend", "frontend"),
        help="Build only one of the images.",
    )
    parser.add_argument(
        "--target",
        default="prod",
        choices=("dev", "prod"),
        help="Dockerfile target stage to build (default: prod).",
    )
    args = parser.parse_args(argv)

    try:
        if args.only in (None, "backend"):
            with section(f"build backend image (target={args.target})"):
                _docker_build(
                    "docker/backend.Dockerfile",
                    f"sastbot-backend:{args.tag}",
                    args.target,
                )
        if args.only in (None, "frontend"):
            with section(f"build frontend image (target={args.target})"):
                _docker_build(
                    "docker/frontend.Dockerfile",
                    f"sastbot-frontend:{args.tag}",
                    args.target,
                )
    except Exception as exc:  # noqa: BLE001
        error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
