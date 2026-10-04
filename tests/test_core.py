from __future__ import annotations

import json

import pytest

from sectools.core import checksums, report
from sectools.core.evidence import Finding, write_evidence


def test_checksum_verify_match(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    expected = checksums.file_digest(f, "sha256")
    result = checksums.verify(f, expected.upper(), "sha256")  # case-insensitive
    assert result.matches is True


def test_checksum_verify_mismatch_and_none(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    assert checksums.verify(f, "deadbeef", "md5").matches is False
    assert checksums.verify(f, None, "md5").matches is None


def test_checksum_rejects_unknown_algorithm(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"x")
    with pytest.raises(ValueError):
        checksums.file_digest(f, "crc32")


def test_report_table_escapes_pipes():
    rendered = report.table(["A", "B"], [("x|y", "z")])
    assert "x\\|y" in rendered
    assert rendered.count("\n") == 2  # header, separator, one row


def test_write_evidence_creates_files(tmp_path):
    finding = Finding(tool="demo", summary="ok", data={"n": 1}, markdown="# hi")
    written = write_evidence(finding, tmp_path / "ev")
    assert len(written) == 2
    payload = json.loads(written[0].read_text())
    assert payload["tool"] == "demo"
    assert payload["data"]["n"] == 1
