"""Verify the integrity of a file against an expected checksum.

A thin CLI wrapper around :mod:`sectools.core.checksums`, because confirming an
input's integrity is the first step of every analysis.

Example:
    sectools verify --file sample.zip --expected be3c...6331 --algorithm md5
"""

from __future__ import annotations

import argparse

from sectools.core import checksums, report
from sectools.core.evidence import Finding

NAME = "verify"
HELP = "compute and (optionally) verify a file checksum"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", required=True, help="file to hash")
    parser.add_argument("--expected", help="expected checksum to compare against")
    parser.add_argument(
        "--algorithm",
        default="sha256",
        choices=checksums.ALGORITHMS,
        help="hash algorithm (default: sha256)",
    )


def run(args: argparse.Namespace) -> Finding:
    result = checksums.verify(args.file, args.expected, args.algorithm)
    warnings = []
    if result.matches is False:
        warnings.append("checksum MISMATCH")
    status = {None: "computed", True: "MATCH", False: "MISMATCH"}[result.matches]
    md = (
        report.heading("Checksum verification", 2)
        + "\n\n"
        + report.key_values(
            {
                "File": result.path,
                "Algorithm": result.algorithm,
                "Computed": result.computed,
                "Expected": result.expected or "n/a",
                "Result": status,
            }
        )
    )
    return Finding(
        tool=NAME,
        summary=f"{result.algorithm}: {status}",
        data=result.as_dict(),
        markdown=md,
        warnings=warnings,
    )
