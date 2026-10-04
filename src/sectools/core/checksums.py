"""File integrity helpers: compute and verify common checksums.

Verifying the integrity of an input file before analysing it is the first step of
almost every forensic workflow, so it lives in the shared core.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Algorithms we expose on the CLI. Keyed by the lowercase name the user types.
ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

_CHUNK = 1024 * 1024  # 1 MiB: stream large files instead of reading them whole.


def file_digest(path: str | Path, algorithm: str = "sha256") -> str:
    """Return the hex digest of ``path`` using ``algorithm`` (streamed)."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {algorithm!r}; choose from {ALGORITHMS}")
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class ChecksumResult:
    """Outcome of comparing a computed digest against an expected one."""

    path: str
    algorithm: str
    computed: str
    expected: str | None
    matches: bool | None  # None when no expected value was supplied

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "algorithm": self.algorithm,
            "computed": self.computed,
            "expected": self.expected,
            "matches": self.matches,
        }


def verify(path: str | Path, expected: str | None, algorithm: str = "sha256") -> ChecksumResult:
    """Compute the digest of ``path`` and compare it to ``expected`` if given.

    The comparison is case-insensitive because checksum strings are published in
    both upper and lower case.
    """
    computed = file_digest(path, algorithm)
    matches = None if expected is None else computed.lower() == expected.strip().lower()
    return ChecksumResult(
        path=str(path),
        algorithm=algorithm.lower(),
        computed=computed,
        expected=expected,
        matches=matches,
    )
