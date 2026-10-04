"""Command-line entry point for sectools.

Builds one subcommand per tool in :data:`sectools.tools.TOOLS` and wires in the
shared output options (``--json`` and ``--evidence``).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from sectools import __version__
from sectools.core.evidence import Finding, write_evidence
from sectools.tools import TOOLS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sectools",
        description="Automated CLI utilities for everyday security analysis.",
    )
    parser.add_argument("--version", action="version", version=f"sectools {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<tool>", required=True)

    for tool in TOOLS:
        sub = subparsers.add_parser(tool.NAME, help=tool.HELP, description=tool.__doc__)
        tool.add_arguments(sub)
        _add_common_output_args(sub)
        sub.set_defaults(_run=tool.run)

    return parser


def _add_common_output_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--json", action="store_true", help="print the finding as JSON")
    group.add_argument(
        "--evidence",
        metavar="DIR",
        help="also write a JSON + Markdown evidence record into DIR",
    )


def _emit(finding: Finding, args: argparse.Namespace) -> None:
    if args.json:
        print(finding.to_json())
    else:
        print(finding.summary)
        if finding.markdown:
            print()
            print(finding.markdown)
        for warning in finding.warnings:
            print(f"[!] {warning}", file=sys.stderr)

    if args.evidence:
        written = write_evidence(finding, args.evidence)
        for path in written:
            print(f"[evidence] {path}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        finding = args._run(args)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(finding, args)
    # 0 = ran successfully (warnings are informational), 2 = execution error.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
