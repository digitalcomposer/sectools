"""Scan a host's TLS *posture*: protocol versions, cipher suites and known flaws.

Where :mod:`sectools.tools.certscan` answers "what is in the certificate and when
does it expire", ``tlsscan`` answers "which TLS/SSL versions, ciphers and known
vulnerabilities (Heartbleed, ROBOT, POODLE, ...) does this endpoint expose".

It has no native TLS stack of its own; instead it drives whichever established
scanner is installed, preferring the one with the most structured output:

  1. ``sslyze``   -- Python package (``pip install "sectools[tls]"``), structured JSON.
  2. ``sslscan``  -- CLI, parsed from its ``--xml`` output.
  3. ``testssl.sh`` -- CLI, parsed from its ``--jsonfile`` output (most thorough, slowest).

Run ``sectools doctor`` to see which of these are present and how to install them.

DISCLAIMER: Only scan hosts you are authorised to test.

Example:
    sectools tlsscan --host example.com --ports 443 --json
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "tlsscan"
HELP = "scan a host's TLS posture (protocol versions, ciphers, known vulnerabilities)"

ENGINES = ("sslyze", "sslscan", "testssl")

# Canonical protocol names, ordered oldest -> newest.
_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
# Protocols considered deprecated/unsafe when still enabled.
DEPRECATED_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})

# sslscan "<protocol type=.. version=..>" -> canonical name.
_SSLSCAN_PROTO = {
    ("ssl", "2"): "SSLv2",
    ("ssl", "3"): "SSLv3",
    ("tls", "1.0"): "TLSv1.0",
    ("tls", "1.1"): "TLSv1.1",
    ("tls", "1.2"): "TLSv1.2",
    ("tls", "1.3"): "TLSv1.3",
}
# testssl "id" -> canonical protocol name.
_TESTSSL_PROTO = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLSv1.0",
    "TLS1_1": "TLSv1.1",
    "TLS1_2": "TLSv1.2",
    "TLS1_3": "TLSv1.3",
}
# testssl vulnerability "id"s we surface (severity decides whether it is a hit).
_TESTSSL_VULNS = (
    "heartbleed",
    "CCS",
    "ticketbleed",
    "ROBOT",
    "secure_client_renego",
    "CRIME_TLS",
    "BREACH",
    "POODLE_SSL",
    "SWEET32",
    "FREAK",
    "DROWN",
    "LOGJAM",
    "BEAST",
    "LUCKY13",
    "winshock",
    "RC4",
)
_BAD_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


class EngineError(RuntimeError):
    """Raised when no usable scanning engine is available."""


def _testssl_path() -> str | None:
    return shutil.which("testssl.sh") or shutil.which("testssl")


def available_engines() -> dict[str, bool]:
    """Return which engines can run on this machine."""
    sslyze_ok = False
    try:
        import sslyze  # noqa: F401

        sslyze_ok = True
    except ImportError:
        sslyze_ok = False
    return {
        "sslyze": sslyze_ok,
        "sslscan": shutil.which("sslscan") is not None,
        "testssl": _testssl_path() is not None,
    }


def select_engine(preferred: str = "auto") -> str:
    """Pick an engine, honouring ``preferred`` or falling back by priority."""
    present = available_engines()
    if preferred != "auto":
        if not present.get(preferred):
            raise EngineError(f"requested engine {preferred!r} is not installed")
        return preferred
    for engine in ENGINES:
        if present[engine]:
            return engine
    raise EngineError(
        "no TLS scanner found; install one of: "
        'pip install "sectools[tls]" (sslyze), sslscan, or testssl.sh'
    )


def _blank_result() -> dict[str, Any]:
    return {
        "protocols": dict.fromkeys(_PROTOCOLS),
        "ciphers": [],
        "weak_ciphers": [],
        "vulnerabilities": {},
    }


def _is_weak_cipher(name: str, bits: int | None, strength: str | None) -> bool:
    if strength and strength.lower() in {"weak", "null"}:
        return True
    if bits is not None and bits < 112:
        return True
    upper = name.upper()
    bad_markers = ("RC4", "_DES", "-DES", "3DES", "NULL", "EXPORT", "MD5", "ANON")
    return any(marker in upper for marker in bad_markers)


# --- parsers (pure, unit-testable without network) -------------------------


def _xml_fromstring(xml_text: str) -> Any:
    """Parse XML with entity-expansion attacks disabled.

    ``defusedxml`` is used when installed (it ships with ``sectools[tls]``); otherwise
    we fall back to the stdlib parser with a parser that rejects DTDs, so a hostile
    ``sslscan`` output cannot mount a billion-laughs / external-entity attack.
    """
    try:
        from defusedxml.ElementTree import fromstring as _defused_fromstring

        return _defused_fromstring(xml_text)
    except ImportError:
        import xml.etree.ElementTree as ET

        # A billion-laughs / external-entity attack needs an inline DTD or entity
        # definition; the stdlib parser never fetches external entities, so refusing
        # any DOCTYPE/ENTITY markup closes the remaining hole without a dependency.
        if re.search(r"<!DOCTYPE|<!ENTITY", xml_text, flags=re.IGNORECASE):
            raise ValueError("DTD/entity declarations are not allowed here") from None
        return ET.fromstring(xml_text)  # noqa: S314 - DTDs rejected above


def _parse_sslscan_xml(xml_text: str) -> dict[str, Any]:
    result = _blank_result()
    root = _xml_fromstring(xml_text)
    test = root.find("ssltest")
    if test is None:
        return result

    for proto in test.findall("protocol"):
        canonical = _SSLSCAN_PROTO.get((proto.get("type", ""), proto.get("version", "")))
        if canonical:
            result["protocols"][canonical] = proto.get("enabled") == "1"

    for cipher in test.findall("cipher"):
        name = cipher.get("cipher", "")
        bits = int(cipher.get("bits")) if cipher.get("bits", "").isdigit() else None
        strength = cipher.get("strength")
        result["ciphers"].append(name)
        if _is_weak_cipher(name, bits, strength):
            result["weak_ciphers"].append(name)

    heartbleed = any(hb.get("vulnerable") == "1" for hb in test.findall("heartbleed"))
    result["vulnerabilities"]["heartbleed"] = heartbleed
    return result


def _parse_testssl_json(entries: list[dict[str, Any]]) -> dict[str, Any]:
    result = _blank_result()
    for entry in entries:
        ident = entry.get("id", "")
        finding = (entry.get("finding") or "").lower()
        severity = (entry.get("severity") or "").upper()

        if ident in _TESTSSL_PROTO:
            offered = "offered" in finding and "not offered" not in finding
            result["protocols"][_TESTSSL_PROTO[ident]] = offered
        elif ident in _TESTSSL_VULNS:
            result["vulnerabilities"][ident] = severity in _BAD_SEVERITIES or (
                "vulnerable" in finding and "not vulnerable" not in finding
            )
    return result


# --- engine drivers --------------------------------------------------------


def _run(argv: list[str], timeout: float, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, capture_output=True, timeout=timeout, **kwargs)  # noqa: S603


def _scan_with_sslscan(host: str, port: int, timeout: float) -> dict[str, Any]:
    proc = _run(
        ["sslscan", "--no-colour", "--xml=-", f"{host}:{port}"],  # noqa: S607 - name resolved via PATH
        timeout=timeout,
    )
    xml_text = proc.stdout.decode("utf-8", "replace")
    if not xml_text.strip():
        raise EngineError(f"sslscan produced no output for {host}:{port}")
    result = _parse_sslscan_xml(xml_text)
    result["engine"] = "sslscan"
    return result


def _scan_with_testssl(host: str, port: int, timeout: float) -> dict[str, Any]:
    binary = _testssl_path()
    if binary is None:  # pragma: no cover - guarded by select_engine
        raise EngineError("testssl.sh not found")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "testssl.json"
        argv = [binary, "--quiet", "--jsonfile", str(out)]
        argv += ["--protocols", "--vulnerable", f"{host}:{port}"]
        _run(argv, timeout=timeout)
        if not out.exists():
            raise EngineError(f"testssl.sh produced no output for {host}:{port}")
        entries = json.loads(out.read_text(encoding="utf-8", errors="replace"))
    result = _parse_testssl_json(entries)
    result["engine"] = "testssl"
    return result


_SSLYZE_PROTO = {
    "ssl_2_0_cipher_suites": "SSLv2",
    "ssl_3_0_cipher_suites": "SSLv3",
    "tls_1_0_cipher_suites": "TLSv1.0",
    "tls_1_1_cipher_suites": "TLSv1.1",
    "tls_1_2_cipher_suites": "TLSv1.2",
    "tls_1_3_cipher_suites": "TLSv1.3",
}


def _sslyze_done(attempt: Any) -> bool:
    """True when a scan-command attempt completed and carries a result."""
    from sslyze import ScanCommandAttemptStatusEnum

    return (
        attempt is not None
        and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and attempt.result is not None
    )


def _scan_with_sslyze(host: str, port: int, timeout: float) -> dict[str, Any]:  # noqa: ARG001
    from sslyze import (
        ScanCommand,
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ServerScanStatusEnum,
    )

    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port),
        scan_commands={
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.OPENSSL_CCS_INJECTION,
        },
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    result = _blank_result()
    result["engine"] = "sslyze"

    for server_result in scanner.get_results():
        if server_result.scan_status != ServerScanStatusEnum.COMPLETED:
            status = server_result.scan_status.name
            raise EngineError(f"sslyze could not connect to {host}:{port} ({status})")
        sr = server_result.scan_result
        assert sr is not None  # noqa: S101 - guaranteed by the COMPLETED status above

        for attr, proto in _SSLYZE_PROTO.items():
            attempt: Any = getattr(sr, attr, None)
            if not _sslyze_done(attempt):
                continue
            accepted = list(attempt.result.accepted_cipher_suites)
            result["protocols"][proto] = bool(accepted)
            for suite in accepted:
                cs = suite.cipher_suite
                result["ciphers"].append(cs.name)
                if cs.is_anonymous or _is_weak_cipher(cs.name, cs.key_size, None):
                    result["weak_ciphers"].append(cs.name)

        # Vulnerability probes: go through getattr so a None attempt is simply skipped.
        for attr, key, field in (
            ("heartbleed", "heartbleed", "is_vulnerable_to_heartbleed"),
            ("openssl_ccs_injection", "ccs_injection", "is_vulnerable_to_ccs_injection"),
        ):
            attempt = getattr(sr, attr, None)
            if _sslyze_done(attempt):
                result["vulnerabilities"][key] = bool(getattr(attempt.result, field))
        robot: Any = getattr(sr, "robot", None)
        if _sslyze_done(robot):
            result["vulnerabilities"]["robot"] = (
                "NOT_VULNERABLE" not in robot.result.robot_result.name
            )
    return result


_DRIVERS = {
    "sslyze": _scan_with_sslyze,
    "sslscan": _scan_with_sslscan,
    "testssl": _scan_with_testssl,
}


def scan_host(host: str, port: int, engine: str, timeout: float) -> dict[str, Any]:
    """Scan one ``host:port`` with the chosen engine and return a normalised result."""
    result = _DRIVERS[engine](host, port, timeout)
    result.setdefault("engine", engine)
    result["source"] = f"{host}:{port}"
    enabled = [name for name, on in result["protocols"].items() if on]
    result["supported_protocols"] = enabled
    result["deprecated_enabled"] = [p for p in enabled if p in DEPRECATED_PROTOCOLS]
    result["vulnerable_to"] = sorted(n for n, hit in result["vulnerabilities"].items() if hit)
    return result


# --- presentation ----------------------------------------------------------

# Legacy SSL is the most serious protocol problem; keep it separate from the
# merely-deprecated TLS 1.0/1.1 so the verdict can escalate.
_LEGACY_SSL = frozenset({"SSLv2", "SSLv3"})

GOOD = "✓"
WARN = "⚠"
BAD = "✗"


def assess(res: dict[str, Any]) -> dict[str, Any]:
    """Turn a raw scan result into a human verdict with Good / Issues lists.

    The point is that a reader sees *what is fine and what is not* without having
    to interpret cipher names themselves.
    """
    legacy = [p for p in res["supported_protocols"] if p in _LEGACY_SSL]
    deprecated = [p for p in res["deprecated_enabled"] if p not in _LEGACY_SSL]
    weak = sorted(set(res["weak_ciphers"]))
    vulns = res["vulnerable_to"]
    reachable = bool(res["supported_protocols"] or res["ciphers"])

    issues: list[str] = []
    if not reachable:
        issues.append(f"{WARN} No TLS detected — host may be unreachable or not serving TLS here")
    for v in vulns:
        issues.append(f"{BAD} Vulnerable to {v}")
    for p in legacy:
        issues.append(f"{BAD} Obsolete protocol enabled: {p}")
    for p in deprecated:
        issues.append(f"{WARN} Deprecated protocol enabled: {p}")
    for c in weak:
        issues.append(f"{WARN} Weak cipher accepted: {c}")

    good: list[str] = []
    if reachable:
        if "TLSv1.3" in res["supported_protocols"]:
            good.append(f"{GOOD} Supports TLS 1.3")
        if "TLSv1.2" in res["supported_protocols"] and "TLSv1.3" not in res["supported_protocols"]:
            good.append(f"{GOOD} Supports TLS 1.2")
        if not legacy:
            good.append(f"{GOOD} No obsolete SSLv2/SSLv3")
        if not deprecated:
            good.append(f"{GOOD} No deprecated TLS 1.0/1.1")
        if not weak and res["ciphers"]:
            good.append(f"{GOOD} No weak cipher suites")
        if res["vulnerabilities"] and not vulns:
            good.append(f"{GOOD} No known vulnerabilities in the probes run")

    if not reachable:
        symbol, label = WARN, "not reachable"
    elif vulns or legacy:
        symbol, label = BAD, "insecure"
    elif deprecated or weak:
        symbol, label = WARN, "needs attention"
    else:
        symbol, label = GOOD, "good"

    return {
        "symbol": symbol,
        "label": label,
        "verdict": f"{symbol} {label}",
        "good": good,
        "issues": issues,
    }


def _cell_list(values: list[str], empty: str) -> str:
    return ", ".join(values) if values else empty


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", required=True, help="hostname to scan")
    parser.add_argument("--ports", default="443", help="comma-separated ports (default: 443)")
    parser.add_argument(
        "--engine",
        choices=("auto", *ENGINES),
        default="auto",
        help="scanning engine to use (default: auto -> sslyze, then sslscan, then testssl)",
    )
    parser.add_argument(
        "--timeout", type=float, default=120.0, help="per-port timeout in seconds (default: 120)"
    )


def run(args: argparse.Namespace) -> Finding:
    warnings: list[str] = []
    results: list[dict[str, Any]] = []

    try:
        engine = select_engine(args.engine)
    except EngineError as exc:
        return Finding(
            tool=NAME,
            summary=str(exc),
            data={"engines": available_engines()},
            markdown=report.heading("TLS posture", 2) + "\n\n" + f"_{exc}_",
            warnings=[str(exc)],
        )

    for port in [int(p) for p in args.ports.split(",") if p.strip()]:
        try:
            results.append(scan_host(args.host, port, engine, timeout=args.timeout))
        except (OSError, subprocess.SubprocessError, EngineError, ValueError) as exc:
            warnings.append(f"{args.host}:{port} — {exc}")

    for res in results:
        res["assessment"] = assess(res)
        if not res["supported_protocols"] and not res["ciphers"]:
            # Scanners emit an empty skeleton (exit 0) when they cannot connect,
            # so an all-empty result means "scan failed", not "nothing offered".
            warnings.append(
                f"{res['source']} — no protocols detected; host may be unreachable "
                "or not speaking TLS on this port"
            )
        for proto in res["deprecated_enabled"]:
            warnings.append(f"{res['source']} offers deprecated {proto}")
        for vuln in res["vulnerable_to"]:
            warnings.append(f"{res['source']} vulnerable to {vuln}")
        for weak in sorted(set(res["weak_ciphers"])):
            warnings.append(f"{res['source']} accepts weak cipher {weak}")

    # Overview table: verdict first so the reader sees good/bad before the detail.
    rows = [
        (
            res["source"],
            res["assessment"]["verdict"],
            res["engine"],
            _cell_list(res["supported_protocols"], "none"),
            _cell_list(res["deprecated_enabled"], "none"),
            _cell_list(res["vulnerable_to"], "none found"),
        )
        for res in results
    ]
    md_parts = [
        report.heading("TLS posture", 2),
        f"Verdict key: {GOOD} good · {WARN} needs attention · {BAD} insecure",
        report.table(
            ["Source", "Verdict", "Engine", "Protocols", "Deprecated", "Vulnerabilities"], rows
        ),
    ]

    # Per-endpoint breakdown: exactly what is good and what is not.
    for res in results:
        a = res["assessment"]
        md_parts.append(report.heading(f"{res['source']} — {a['verdict']}", 3))
        if a["issues"]:
            md_parts.append("**Issues to fix**")
            md_parts.append(report.bullet_list(a["issues"]))
        else:
            md_parts.append(f"{GOOD} No issues found.")
        if a["good"]:
            md_parts.append("**What's good**")
            md_parts.append(report.bullet_list(a["good"]))

    md = "\n\n".join(md_parts)

    return Finding(
        tool=NAME,
        summary=f"{len(results)} endpoint(s) scanned via {engine}, {len(warnings)} warning(s)",
        data={"engine": engine, "endpoints": results},
        markdown=md,
        warnings=warnings,
    )
