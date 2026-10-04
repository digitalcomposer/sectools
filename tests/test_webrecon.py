from __future__ import annotations

import json

from sectools.cli import main
from sectools.tools import webrecon


def test_analyze_headers_flags_missing_and_weak_cookies():
    headers = {
        "Server": "nginx/1.25",
        "X-Powered-By": "PHP/8.2",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
    }
    set_cookie = ["sid=abc; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"]
    result = webrecon.analyze_headers(200, headers, set_cookie)

    # CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy are missing.
    assert "content-security-policy" in result["security_headers_missing"]
    assert "strict-transport-security" not in result["security_headers_missing"]
    assert result["fingerprint"]["server"] == "nginx/1.25"
    # The first cookie lacks Secure/HttpOnly/SameSite -> weak.
    assert "sid" in result["weak_cookies"]
    assert "theme" not in result["weak_cookies"]


def test_analyze_headers_all_present():
    headers = dict.fromkeys(webrecon.RECOMMENDED_HEADERS, "x")
    result = webrecon.analyze_headers(200, headers, [])
    assert result["security_headers_missing"] == []


def test_cli_run_with_mocked_fetch(monkeypatch, capsys):
    def fake_fetch(url, timeout=20.0):
        return 200, {"Server": "nginx"}, ["sid=1; Path=/"]

    monkeypatch.setattr(webrecon, "fetch", fake_fetch)
    rc = main(["webrecon", "--url", "https://example.com", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["status"] == 200
    assert "sid" in payload["data"]["weak_cookies"]


def test_cli_rejects_non_http():
    assert main(["webrecon", "--url", "ftp://example.com"]) == 2
