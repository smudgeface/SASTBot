"""Small ANSI-color + section helper for build scripts.

Standard library only. Degrades to plain text when stdout is not a TTY
(e.g. piped to a file on a CI runner).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_RESET = "\033[0m"
_COLORS = {
    "red": "\033[31;1m",
    "green": "\033[32;1m",
    "yellow": "\033[33;1m",
    "blue": "\033[34;1m",
    "cyan": "\033[36;1m",
    "gray": "\033[90m",
    "bold": "\033[1m",
}


def _use_color() -> bool:
    """True when we should emit ANSI escape codes."""
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def paint(text: str, color: str) -> str:
    """Wrap *text* in the given color if colors are enabled."""
    if not _use_color():
        return text
    code = _COLORS.get(color)
    if code is None:
        return text
    return f"{code}{text}{_RESET}"


def info(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print(paint(f"warning: {msg}", "yellow"), flush=True)


def error(msg: str) -> None:
    print(paint(f"error: {msg}", "red"), file=sys.stderr, flush=True)


def success(msg: str) -> None:
    print(paint(msg, "green"), flush=True)


@contextmanager
def section(title: str) -> Iterator[None]:
    """Context manager that frames a step with a coloured header + timing.

    Prints elapsed time on exit; re-raises any exception from the body so
    the script fails with the original traceback.
    """
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    bar = "─" * max(0, term_width - len(title) - 4)
    print(paint(f"\n── {title} {bar}", "cyan"), flush=True)
    start = time.monotonic()
    try:
        yield
    except BaseException:
        elapsed = time.monotonic() - start
        print(paint(f"✗ {title}  ({elapsed:.1f}s)", "red"), flush=True)
        raise
    elapsed = time.monotonic() - start
    print(paint(f"✓ {title}  ({elapsed:.1f}s)", "green"), flush=True)


def repo_root() -> Path:
    """Absolute path to the repo root (directory containing ``scripts/``)."""
    return Path(__file__).resolve().parent.parent


def run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and stream its output.

    Always uses ``text=True``. Returns the completed process. If *check* is
    True (default), non-zero exit raises ``CalledProcessError``.
    """
    cwd = cwd or repo_root()
    print(paint(f"$ {' '.join(args)}", "gray"), flush=True)
    return subprocess.run(
        args,
        cwd=str(cwd),
        env={**os.environ, **(env or {})} if env else None,
        check=check,
        text=True,
    )
