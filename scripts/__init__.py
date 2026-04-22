"""SASTBot build/CI scripts.

Runnable as ``python -m scripts.<name>`` from the repo root. Each module
exports a :func:`run` function returning an integer exit code, and a
``if __name__ == "__main__"`` guard that calls ``sys.exit(run())``.

Standard library only. No pip dependencies. Targets Python 3.9+.
"""

__version__ = "0.1.0"
