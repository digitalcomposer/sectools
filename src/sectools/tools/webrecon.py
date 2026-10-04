"""Passive web reconnaissance: security headers, cookie flags, and tech fingerprint.

This performs a single GET request and inspects the *response* only. It does not
fuzz, brute-force, or send attack payloads. Use it to triage a target's baseline
posture and produce a checklist for a human to follow up on.

DISCLAIMER: Only run this against systems you are authorised to test.

Example:
    sectools webrecon --url https://example.com --json
"""

from __future__ import annotations

import argparse
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from typing import Any

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "webrecon"
HELP = "passively inspect a URL's security headers, cookie flags, and tech fingerprint"

# Response headers every modern site should set, with a one-line rationale.
RECOMMENDED_HEADERS = {
    "content-security-policy": "mitigates XSS and data injection",
    "strict-transport-security": "forces HTTPS (HSTS)",
    "x-content-type-options": "blocks MIME sniffing (nosniff)",
    "x-frame-options": "clickjacking protection (or CSP frame-ancestors)",
    "referrer-policy": "controls referrer leakage",
    "permissions-policy": "restricts powerful browser features",
}

FINGERPRINT_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "via")


def analyze_headers(
    status: int, headers: dict[str, str], set_cookie: list[str] | None = None
) -> dict[str, Any]:
    """Analyse a response: missing security headers, cookie flags, fingerprint."""
    lower = {key.lower(): value for key, value in headers.items()}

    missing = [name for name in RECOMMENDED_HEADERS if name not in lower]
    present = {name: lower[name] for name in RECOMMENDED_HEADERS if name in lower}
    fingerprint = {name: lower[name] for name in FINGERPRINT_HEADERS if name in lower}

    cookies: list[dict[str, Any]] = []
    for raw in set_cookie or []:
        jar = SimpleCookie()
        jar.load(raw)
        for name, morsel in jar.items():
            cookies.append(
                {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                }
            )

    weak_cookies = [
        c["name"] for c in cookies if not c["secure"] or not c["httponly"] or not c["samesite"]
    ]

    return {
        "status": status,
        "security_headers_present": present,
        "security_headers_missing": missing,
        "fingerprint": fingerprint,
        "cookies": cookies,
        "weak_cookies": weak_cookies,
    }


def fetch(url: str, timeout: float = 20.0) -> tuple[int, dict[str, str], list[str]]:
    """GET ``url`` and return ``(status, headers, set_cookie_values)``."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "sectools/0.1 (+webrecon)"}, method="GET"
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - operator input
    except urllib.error.HTTPError as exc:  # treat error responses as inspectable too
        response = exc
    with response:
        headers = dict(response.headers.items())
        set_cookie = response.headers.get_all("Set-Cookie") or []
        return response.status, headers, set_cookie


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", required=True, help="target URL (http/https)")
    parser.add_argument("--timeout", type=float, default=20.0, help="network timeout (seconds)")


def run(args: argparse.Namespace) -> Finding:
    if not args.url.lower().startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")

    status, headers, set_cookie = fetch(args.url, timeout=args.timeout)
    result = analyze_headers(status, headers, set_cookie)
    result["url"] = args.url

    missing = result["security_headers_missing"]
    md_parts = [
        report.heading("Web reconnaissance (passive)", 2),
        report.key_values(
            {
                "URL": args.url,
                "Status": status,
                "Server": result["fingerprint"].get("server", "n/a"),
                "Missing security headers": len(missing),
                "Weak cookies": len(result["weak_cookies"]),
            }
        ),
    ]
    if missing:
        md_parts.append(report.heading("Missing security headers", 3))
        md_parts.append(
            report.bullet_list(f"`{name}` — {RECOMMENDED_HEADERS[name]}" for name in missing)
        )
    md = "\n\n".join(md_parts)

    warnings = [f"missing header: {name}" for name in missing]
    warnings += [f"weak cookie: {name}" for name in result["weak_cookies"]]

    return Finding(
        tool=NAME,
        summary=f"status {status}, {len(missing)} missing header(s), "
        f"{len(result['weak_cookies'])} weak cookie(s)",
        data=result,
        markdown=md,
        warnings=warnings,
    )
