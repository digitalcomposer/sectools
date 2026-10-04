"""Recover a repeating-key XOR key from a known plaintext/ciphertext pair.

Classic known-plaintext attack: if ``cipher = plain XOR key`` with a repeating
key, then ``key = plain XOR cipher``. Given one original file and its XOR-encrypted
counterpart, this recovers the key and can decrypt further files.

Example:
    sectools xorkey --plain logo.jpg --cipher logo.jpg_encrypted --key-length 32 \
        --decrypt report.pdf_encrypted notes.txt_encrypted --out-dir ./decrypted
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "xorkey"
HELP = "recover a repeating-XOR key from a known plaintext/ciphertext pair and decrypt files"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR ``data`` with a repeating ``key``."""
    if not key:
        raise ValueError("key must not be empty")
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def _keystream(plain: bytes, cipher: bytes) -> bytes:
    """Byte-wise XOR of the overlapping prefix of ``plain`` and ``cipher``."""
    n = min(len(plain), len(cipher))
    if n == 0:
        raise ValueError("plaintext and ciphertext must both be non-empty")
    return bytes(plain[i] ^ cipher[i] for i in range(n))


def recover_key(plain: bytes, cipher: bytes, key_length: int) -> bytes:
    """Recover a ``key_length``-byte key, verifying it is consistent.

    Every position ``i`` with ``i % key_length == k`` must reveal the same key
    byte. If they disagree, the inputs do not form a clean repeating-XOR pair and
    we refuse to guess.
    """
    if key_length <= 0:
        raise ValueError("key_length must be positive")
    stream = _keystream(plain, cipher)
    if len(stream) < key_length:
        raise ValueError(f"need at least {key_length} overlapping bytes, got {len(stream)}")
    key = bytearray(stream[:key_length])
    for i, value in enumerate(stream):
        if value != key[i % key_length]:
            raise ValueError(
                f"inconsistent key byte at offset {i}: inputs are not a clean "
                "repeating-XOR pair for this key length"
            )
    return bytes(key)


def detect_key_length(plain: bytes, cipher: bytes, max_length: int = 64) -> int:
    """Return the smallest key length (1..max_length) that is fully consistent."""
    stream = _keystream(plain, cipher)
    limit = min(max_length, len(stream))
    for length in range(1, limit + 1):
        if all(stream[i] == stream[i % length] for i in range(len(stream))):
            return length
    raise ValueError(f"no consistent key length found up to {max_length}")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plain", required=True, help="known original (plaintext) file")
    parser.add_argument("--cipher", required=True, help="XOR-encrypted counterpart of --plain")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--key-length", type=int, help="expected key length in bytes")
    group.add_argument(
        "--detect",
        action="store_true",
        help="auto-detect the smallest consistent key length",
    )
    parser.add_argument("--max-length", type=int, default=64, help="upper bound for --detect")
    parser.add_argument(
        "--decrypt",
        nargs="*",
        default=[],
        metavar="FILE",
        help="additional encrypted files to decrypt with the recovered key",
    )
    parser.add_argument("--out-dir", default=".", help="where to write decrypted files")
    parser.add_argument(
        "--key-json",
        help="also write the recovered key to this JSON file (as a hex string)",
    )


def run(args: argparse.Namespace) -> Finding:
    plain = Path(args.plain).read_bytes()
    cipher = Path(args.cipher).read_bytes()

    if args.detect:
        key_length = detect_key_length(plain, cipher, args.max_length)
    else:
        key_length = args.key_length
    key = recover_key(plain, cipher, key_length)

    decrypted: list[dict[str, str]] = []
    out_dir = Path(args.out_dir)
    for src in args.decrypt:
        src_path = Path(src)
        plaintext = xor_bytes(src_path.read_bytes(), key)
        name = src_path.name
        for suffix in ("_encrypted", ".encrypted", ".enc"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / name
        dest.write_bytes(plaintext)
        decrypted.append({"input": str(src_path), "output": str(dest)})

    key_hex = key.hex()
    if args.key_json:
        Path(args.key_json).write_text(
            json.dumps({"key_hex": key_hex, "key_length": key_length}, indent=2) + "\n",
            encoding="utf-8",
        )

    data = {
        "key_length": key_length,
        "key_hex": key_hex,
        "key_bytes": list(key),
        "decrypted": decrypted,
    }
    md = "\n\n".join(
        [
            report.heading("XOR key recovery", 2),
            report.key_values(
                {
                    "Key length (bytes)": key_length,
                    "Key (hex)": key_hex,
                    "Files decrypted": len(decrypted),
                }
            ),
        ]
    )
    return Finding(
        tool=NAME,
        summary=f"recovered {key_length}-byte key, decrypted {len(decrypted)} file(s)",
        data=data,
        markdown=md,
    )
