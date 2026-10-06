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


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_openssl_fallback_extracts_key_and_signature(fixtures):
    der = certscan._load_der(fixtures / "sample_cert.pem")
    summary = certscan._summarize_with_openssl(der)

    assert summary["engine"] == "openssl"
    # fixture is a 2048-bit RSA cert signed with sha256WithRSAEncryption
    assert summary["key_type"] == "RSA"
    assert summary["key_size"] == 2048
    assert summary["signature_algorithm"] == "sha256WithRSAEncryption"


def test_identity_falls_back_to_san_when_subject_empty():
    cert = {"subject": "", "sans": ["ittrace.ch", "www.ittrace.ch"]}
    assert certscan._identity(cert) == "ittrace.ch, www.ittrace.ch"
    # a real subject still wins
    assert certscan._identity({"subject": "CN=example.test", "sans": []}) == "CN=example.test"
    # nothing at all → placeholder, never a blank cell
    assert certscan._identity({"subject": None, "sans": []}) == "—"


def test_status_verdict():
    assert certscan._status({"expired": True}) == "✗ expired"
    assert certscan._status({"expired": False, "days_until_expiry": 5}) == "⚠ expires in 5d"
    assert certscan._status({"expired": False, "days_until_expiry": 200}).startswith("✓ valid")
    assert certscan._status({"expired": None, "days_until_expiry": None}) == "? unknown"


def test_key_label_combines_type_and_size():
    assert certscan._key_label({"key_type": "RSA", "key_size": 2048}) == "RSA 2048"
    assert certscan._key_label({"key_type": "EC (P-256)", "key_size": 256}) == "EC (P-256)"
    assert certscan._key_label({"key_type": None, "key_size": None}) is None


@pytest.mark.skipif(not _has_engine, reason="needs cryptography or the openssl CLI")
def test_cli_run_from_file(fixtures, capsys):
    from sectools.cli import main

    rc = main(["certscan", "--file", str(fixtures / "sample_cert.pem"), "--json"])
    assert rc == 0
    import json

    payload = json.loads(capsys.readouterr().out)
    certs = payload["data"]["certificates"]
    assert len(certs) == 1
    assert "example.test" in (certs[0]["subject"] or "")
    assert certs[0]["expired"] is False
