"""Command line entry point.

Milestone M0 provides the executable skeleton only: version and a command registry that
the pipeline milestone (M1) fills in with ``run``, ``validate-config`` and ``self-test``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from soc_connectors.version import __version__


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser shared by ``main`` and the tests."""
    parser = argparse.ArgumentParser(
        prog="soc-connectors",
        description="Fetch, normalize and forward security events.",
        epilog="Pipeline commands (run, validate-config, self-test) arrive with milestone M1.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    parser.parse_args(list(argv) if argv is not None else None)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
