"""Umbrella CI runner — typecheck → lint → test → check_openapi → build_images.

Fails fast: the first step that returns a non-zero exit aborts the rest.

Usage::

    python -m scripts.ci                # full pipeline
    python -m scripts.ci --skip-build   # skip slow image build
    python -m scripts.ci --only lint    # run a single step

Designed to be wired into whatever build runner LMI points at it. Returns
exit code 0 on success, non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from . import build_images, check_openapi, lint, test, typecheck
from ._console import error, info, section, success

Step = tuple[str, Callable[[], int]]

ALL_STEPS: list[Step] = [
    ("typecheck", typecheck.run),
    ("lint", lint.run),
    ("test", test.run),
    ("check_openapi", check_openapi.run),
    ("build_images", lambda: build_images.run(["--target", "prod"])),
]


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SASTBot CI pipeline.")
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip the Docker image build step (faster local runs).",
    )
    parser.add_argument(
        "--only",
        choices=[name for name, _ in ALL_STEPS],
        help="Run a single step instead of the whole pipeline.",
    )
    args = parser.parse_args(argv)

    steps: list[Step]
    if args.only:
        steps = [s for s in ALL_STEPS if s[0] == args.only]
    else:
        steps = ALL_STEPS
        if args.skip_build:
            steps = [s for s in steps if s[0] != "build_images"]

    info(f"running steps: {', '.join(name for name, _ in steps)}")
    for name, step in steps:
        with section(f"CI step: {name}"):
            code = step()
            if code != 0:
                error(f"step '{name}' failed with exit code {code}")
                return code

    success("\n✔ all CI steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(run())
