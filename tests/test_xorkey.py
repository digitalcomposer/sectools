from __future__ import annotations

import json

import pytest

from sectools.cli import main
from sectools.tools import xorkey


def test_xor_bytes_roundtrip():
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    data = b"the quick brown fox" * 10
    cipher = xorkey.xor_bytes(data, key)
    assert cipher != data
    assert xorkey.xor_bytes(cipher, key) == data


def test_recover_key_known_plaintext():
    key = bytes(range(32))
    plain = bytes((i * 7) % 256 for i in range(200))
    cipher = xorkey.xor_bytes(plain, key)
    assert xorkey.recover_key(plain, cipher, 32) == key


def test_recover_key_rejects_inconsistent_inputs():
    key = bytes(range(32))
    plain = bytes((i * 7) % 256 for i in range(200))
    cipher = bytearray(xorkey.xor_bytes(plain, key))
    cipher[50] ^= 0xFF  # corrupt one byte -> inconsistent key byte
    with pytest.raises(ValueError, match="inconsistent"):
        xorkey.recover_key(plain, bytes(cipher), 32)


def test_detect_key_length():
    key = b"abcd"
    plain = bytes((i * 3) % 256 for i in range(400))
    cipher = xorkey.xor_bytes(plain, key)
    assert xorkey.detect_key_length(plain, cipher, max_length=16) == 4


def test_cli_end_to_end(tmp_path, capsys):
    key = bytes((i * 11) % 256 for i in range(32))
    original = tmp_path / "logo.jpg"
    original.write_bytes(bytes((i * 5) % 256 for i in range(512)))
    enc = tmp_path / "logo.jpg_encrypted"
    enc.write_bytes(xorkey.xor_bytes(original.read_bytes(), key))

    secret_plain = b"TOP SECRET CONTENTS " * 20
    secret_enc = tmp_path / "secret.txt_encrypted"
    secret_enc.write_bytes(xorkey.xor_bytes(secret_plain, key))

    key_json = tmp_path / "key.json"
    out_dir = tmp_path / "out"

    rc = main(
        [
            "xorkey",
            "--plain",
            str(original),
            "--cipher",
            str(enc),
            "--key-length",
            "32",
            "--decrypt",
            str(secret_enc),
            "--out-dir",
            str(out_dir),
            "--key-json",
            str(key_json),
            "--json",
        ]
    )
    assert rc == 0

    saved = json.loads(key_json.read_text())
    assert saved["key_hex"] == key.hex()
    assert (out_dir / "secret.txt").read_bytes() == secret_plain
