from __future__ import annotations

import shutil

import pytest

from sectools.tools import certscan

_has_engine = shutil.which("openssl") is not None
try:  # cryptography is optional but also satisfies the engine requirement
    import cryptography  # noqa: F401

    _has_engine = True
except ImportError:
    pass


@pytest.mark.skipif(not _has_engine, reason="needs cryptography or the openssl CLI")
def test_summarize_certificate_from_pem(fixtures):
    der = certscan._load_der(fixtures / "sample_cert.pem")
    summary = certscan.summarize_certificate(der)

    assert "example.test" in (summary["subject"] or "")
    assert "example.test" in summary["sans"]
    assert summary["not_after"] is not None
    assert summary["days_until_expiry"] is not None
    assert summary["expired"] is False  # fixture is valid for ~825 days


def test_load_der_detects_pem(fixtures):
    der = certscan._load_der(fixtures / "sample_cert.pem")
    assert der[:1] == b"\x30"  # DER SEQUENCE tag
