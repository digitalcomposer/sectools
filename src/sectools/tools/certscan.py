"""Analyse X.509/TLS certificates from a live host or from files on disk.

Two modes:
  * ``--host example.com --ports 443,8443`` grabs the certificate presented on
    each port (no validation, so self-signed certs are inspected too).
  * ``--file cert.pem`` / ``--file cert.der`` parses a certificate from disk.

Parsing uses the ``cryptography`` library when installed (``pip install
sectools[certs]``) and otherwise falls back to the system ``openssl`` CLI, so the
tool works out of the box on most systems.

DISCLAIMER: Only scan hosts you are authorised to test.

Example:
    sectools certscan --host example.com --ports 443 --json
"""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "certscan"
HELP = "scan a host for TLS certificates or analyse certificate files (expiry, SANs, keys)"


def get_peer_der(host: str, port: int, timeout: float = 10.0) -> bytes:
    """Open a TLS connection and return the peer certificate in DER form."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we inspect, we do not validate
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError(f"no certificate returned by {host}:{port}")
    return der


def _parse_openssl_date(value: str) -> str | None:
    value = value.strip().removesuffix(" GMT")
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return parsed.isoformat()


def _summarize_with_openssl(der: bytes) -> dict[str, Any]:
    """Fallback summary using the system ``openssl`` CLI."""
    base = ["openssl", "x509", "-inform", "DER", "-noout", "-nameopt", "RFC2253"]
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            *base,
            "-subject",
            "-issuer",
            "-serial",
            "-startdate",
            "-enddate",
            "-ext",
            "subjectAltName",
            "-text",  # also dump the human-readable body so we can read the key/signature
        ],
        input=der,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8", "replace")

    def grab(prefix: str) -> str | None:
        match = re.search(rf"^{prefix}=(.*)$", out, flags=re.MULTILINE)
        return match.group(1).strip() if match else None

    sans_line = ""
    # openssl prints the long extension name, e.g. "X509v3 Subject Alternative Name:".
    san_match = re.search(r"Subject Alternative Name:[^\n]*\n\s*(.+)", out)
    if san_match:
        sans_line = san_match.group(1)
    sans = [s.strip().removeprefix("DNS:") for s in sans_line.split(",") if s.strip()]

    key_type, key_size = _parse_openssl_key(out)

    not_before = _parse_openssl_date(grab("notBefore") or "")
    not_after = _parse_openssl_date(grab("notAfter") or "")
    return {
        "subject": grab("subject"),
        "issuer": grab("issuer"),
        "serial": grab("serial"),
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        # The signature algorithm is printed once per structure; the first hit is the cert's.
        "signature_algorithm": _search1(r"Signature Algorithm:\s*(\S+)", out),
        "key_type": key_type,
        "key_size": key_size,
        "engine": "openssl",
    }


def _search1(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _parse_openssl_key(text: str) -> tuple[str | None, int | None]:
    """Derive ``(key_type, key_size)`` from ``openssl x509 -text`` output."""
    size_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    key_size = int(size_match.group(1)) if size_match else None

    algo = _search1(r"Public Key Algorithm:\s*(\S+)", text)
    if algo is None:
        return None, key_size
    if "rsa" in algo.lower():
        return "RSA", key_size
    if "ec" in algo.lower() or "ecdsa" in algo.lower():
        curve = _search1(r"NIST CURVE:\s*(\S+)", text) or _search1(r"ASN1 OID:\s*(\S+)", text)
        return (f"EC ({curve})" if curve else "EC"), key_size
    return algo, key_size


def _summarize_with_cryptography(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    cert = x509.load_der_x509_certificate(der)
    try:
        sans = [
            str(n.value)
            for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ]
    except x509.ExtensionNotFound:
        sans = []

    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_size = None
    if isinstance(public_key, (rsa.RSAPublicKey,)):
        key_type, key_size = "RSA", public_key.key_size
    elif isinstance(public_key, (ec.EllipticCurvePublicKey,)):
        key_type, key_size = f"EC ({public_key.curve.name})", public_key.curve.key_size

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sans": sans,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "key_type": key_type,
        "key_size": key_size,
        "engine": "cryptography",
    }


def summarize_certificate(der: bytes) -> dict[str, Any]:
    """Summarise a DER certificate, preferring ``cryptography`` over ``openssl``."""
    try:
        summary = _summarize_with_cryptography(der)
    except ImportError:
        summary = _summarize_with_openssl(der)

    if summary.get("not_after"):
        expiry = datetime.fromisoformat(summary["not_after"])
        now = datetime.now(timezone.utc)
        summary["days_until_expiry"] = (expiry - now).days
        summary["expired"] = expiry < now
    else:
        summary["days_until_expiry"] = None
        summary["expired"] = None
    return summary


def _load_der(path: str | Path) -> bytes:
    raw = Path(path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        return ssl.PEM_cert_to_DER_cert(raw.decode("ascii", "replace"))
    return raw


def add_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="hostname to scan for TLS certificates")
    group.add_argument("--file", nargs="+", metavar="CERT", help="certificate file(s) to analyse")
    parser.add_argument("--ports", default="443", help="comma-separated ports for --host")
    parser.add_argument("--timeout", type=float, default=10.0, help="connection timeout (seconds)")


def _identity(cert: dict[str, Any]) -> str:
    """Best human-readable identity: the subject DN, or the SANs when it is empty.

    Modern CAs (e.g. Let's Encrypt) issue certs with an empty Subject DN and carry
    the hostname(s) only in the SAN extension, so a subject-only column is blank for
    the most common certificates on the web.
    """
    subject = (cert.get("subject") or "").strip()
    if subject:
        return subject
    sans = cert.get("sans") or []
    return ", ".join(sans) if sans else "—"


def _key_label(cert: dict[str, Any]) -> str | None:
    """Render ``key_type``/``key_size`` as one cell, e.g. ``RSA 2048`` or ``EC (P-256)``."""
    key_type = cert.get("key_type")
    if not key_type:
        return None
    key_size = cert.get("key_size")
    if key_size and "(" not in key_type:  # avoid "EC (P-256) 256"
        return f"{key_type} {key_size}"
    return key_type


def _status(cert: dict[str, Any]) -> str:
    """One-glance expiry verdict: ✗ expired, ⚠ expiring soon, ✓ valid."""
    if cert.get("expired"):
        return "✗ expired"
    days = cert.get("days_until_expiry")
    if days is None:
        return "? unknown"
    if days < 30:
        return f"⚠ expires in {days}d"
    return f"✓ valid ({days}d)"


def run(args: argparse.Namespace) -> Finding:
    results: list[dict[str, Any]] = []
    warnings: list[str] = []

    if args.host:
        for port in [int(p) for p in args.ports.split(",") if p.strip()]:
            try:
                der = get_peer_der(args.host, port, timeout=args.timeout)
            except OSError as exc:
                warnings.append(f"{args.host}:{port} — {exc}")
                continue
            summary = summarize_certificate(der)
            summary["source"] = f"{args.host}:{port}"
            results.append(summary)
    else:
        for path in args.file:
            summary = summarize_certificate(_load_der(path))
            summary["source"] = str(path)
            results.append(summary)

    for cert in results:
        if cert.get("expired"):
            warnings.append(f"EXPIRED: {cert['source']} (since {cert['not_after']})")
        elif cert.get("days_until_expiry") is not None and cert["days_until_expiry"] < 30:
            warnings.append(
                f"expiring soon: {cert['source']} in {cert['days_until_expiry']} day(s)"
            )

    rows = [
        (
            cert["source"],
            _status(cert),
            _identity(cert),
            cert.get("issuer"),
            cert.get("not_after"),
            _key_label(cert),
        )
        for cert in results
    ]
    md = (
        report.heading("Certificate analysis", 2)
        + "\n\n"
        + "Status key: ✓ valid · ⚠ expiring soon (<30d) · ✗ expired\n\n"
        + report.table(["Source", "Status", "Subject / SAN", "Issuer", "Not after", "Key"], rows)
    )

    return Finding(
        tool=NAME,
        summary=f"{len(results)} certificate(s), {len(warnings)} warning(s)",
        data={"certificates": results},
        markdown=md,
        warnings=warnings,
    )
