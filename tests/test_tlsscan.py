from __future__ import annotations

import argparse

import pytest

from sectools.tools import tlsscan

# A trimmed but format-accurate sslscan --xml document: SSLv3 still enabled
# (deprecated), TLS 1.2/1.3 enabled, one weak (RC4) and one strong cipher,
# heartbleed not vulnerable.
SSLSCAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results">
  <ssltest host="example.test" port="443">
    <protocol type="ssl" version="2" enabled="0" />
    <protocol type="ssl" version="3" enabled="1" />
    <protocol type="tls" version="1.0" enabled="0" />
    <protocol type="tls" version="1.1" enabled="0" />
    <protocol type="tls" version="1.2" enabled="1" />
    <protocol type="tls" version="1.3" enabled="1" />
    <cipher status="accepted" bits="128" cipher="ECDHE-RSA-RC4-SHA" strength="weak" />
    <cipher status="preferred" bits="256" cipher="TLS_AES_256_GCM_SHA384" strength="strong" />
    <heartbleed sslversion="TLSv1.3" vulnerable="0" />
    <heartbleed sslversion="TLSv1.2" vulnerable="0" />
  </ssltest>
</document>
"""

# testssl.sh --jsonfile output: TLS 1.0 offered (deprecated), ROBOT a hit,
# heartbleed clean.
TESTSSL_JSON = [
    {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
    {"id": "SSLv3", "severity": "OK", "finding": "not offered"},
    {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_1", "severity": "INFO", "finding": "not offered"},
    {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
    {"id": "TLS1_3", "severity": "OK", "finding": "offered with final"},
    {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable, no heartbeat extension"},
    {"id": "ROBOT", "severity": "MEDIUM", "finding": "VULNERABLE, RSA key transport cipher"},
]


def test_parse_sslscan_xml():
    res = tlsscan._parse_sslscan_xml(SSLSCAN_XML)
    assert res["protocols"]["SSLv3"] is True
    assert res["protocols"]["TLSv1.0"] is False
    assert res["protocols"]["TLSv1.3"] is True
    assert "ECDHE-RSA-RC4-SHA" in res["weak_ciphers"]
    assert "TLS_AES_256_GCM_SHA384" not in res["weak_ciphers"]
    assert res["vulnerabilities"]["heartbleed"] is False


def test_parse_testssl_json():
    res = tlsscan._parse_testssl_json(TESTSSL_JSON)
    assert res["protocols"]["TLSv1.0"] is True
    assert res["protocols"]["TLSv1.1"] is False
    assert res["protocols"]["TLSv1.2"] is True
    assert res["vulnerabilities"]["ROBOT"] is True
    assert res["vulnerabilities"]["heartbleed"] is False


def test_scan_host_normalises(monkeypatch):
    monkeypatch.setitem(
        tlsscan._DRIVERS, "sslscan", lambda h, p, t: tlsscan._parse_sslscan_xml(SSLSCAN_XML)
    )
    res = tlsscan.scan_host("example.test", 443, "sslscan", timeout=1.0)
    assert res["source"] == "example.test:443"
    assert "SSLv3" in res["deprecated_enabled"]
    assert "TLSv1.2" in res["supported_protocols"]
    assert res["vulnerable_to"] == []  # only heartbleed probed, and it was clean


def test_select_engine_prefers_declared_order(monkeypatch):
    monkeypatch.setattr(
        tlsscan,
        "available_engines",
        lambda: {"sslyze": False, "sslscan": True, "testssl": True},
    )
    assert tlsscan.select_engine("auto") == "sslscan"
    assert tlsscan.select_engine("testssl") == "testssl"


def test_select_engine_raises_when_none(monkeypatch):
    monkeypatch.setattr(
        tlsscan,
        "available_engines",
        lambda: {"sslyze": False, "sslscan": False, "testssl": False},
    )
    with pytest.raises(tlsscan.EngineError):
        tlsscan.select_engine("auto")


def test_select_engine_rejects_missing_requested(monkeypatch):
    monkeypatch.setattr(
        tlsscan,
        "available_engines",
        lambda: {"sslyze": False, "sslscan": True, "testssl": False},
    )
    with pytest.raises(tlsscan.EngineError):
        tlsscan.select_engine("sslyze")


def test_run_without_engine_is_graceful(monkeypatch):
    monkeypatch.setattr(
        tlsscan,
        "available_engines",
        lambda: {"sslyze": False, "sslscan": False, "testssl": False},
    )
    args = argparse.Namespace(host="example.test", ports="443", engine="auto", timeout=1.0)
    finding = tlsscan.run(args)
    assert finding.warnings  # tells the user no scanner is installed
    assert "no TLS scanner" in finding.summary


def test_run_warns_when_scan_comes_back_empty(monkeypatch):
    # A scanner that cannot connect returns an empty skeleton with exit 0.
    monkeypatch.setattr(
        tlsscan, "available_engines", lambda: {"sslyze": False, "sslscan": True, "testssl": False}
    )
    monkeypatch.setitem(tlsscan._DRIVERS, "sslscan", lambda h, p, t: tlsscan._blank_result())
    args = argparse.Namespace(host="example.test", ports="443", engine="auto", timeout=1.0)
    finding = tlsscan.run(args)
    assert any("no protocols detected" in w for w in finding.warnings)


def _normalised(**over):
    base = {
        "protocols": {},
        "ciphers": ["X"],
        "weak_ciphers": [],
        "vulnerabilities": {"heartbleed": False},
        "supported_protocols": ["TLSv1.2", "TLSv1.3"],
        "deprecated_enabled": [],
        "vulnerable_to": [],
    }
    base.update(over)
    return base


def test_assess_good_endpoint():
    a = tlsscan.assess(_normalised())
    assert a["symbol"] == tlsscan.GOOD
    assert a["label"] == "good"
    assert not a["issues"]
    assert any("TLS 1.3" in g for g in a["good"])


def test_assess_insecure_on_vuln_or_legacy_ssl():
    a = tlsscan.assess(
        _normalised(
            supported_protocols=["SSLv3", "TLSv1.2"],
            deprecated_enabled=["SSLv3"],
            vulnerabilities={"robot": True},
            vulnerable_to=["robot"],
        )
    )
    assert a["symbol"] == tlsscan.BAD
    assert any("Vulnerable to robot" in i for i in a["issues"])
    assert any("Obsolete protocol enabled: SSLv3" in i for i in a["issues"])


def test_assess_needs_attention_on_deprecated_and_weak():
    a = tlsscan.assess(
        _normalised(
            supported_protocols=["TLSv1.0", "TLSv1.2", "TLSv1.3"],
            deprecated_enabled=["TLSv1.0"],
            weak_ciphers=["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
        )
    )
    assert a["symbol"] == tlsscan.WARN
    assert any("Deprecated protocol enabled: TLSv1.0" in i for i in a["issues"])
    assert any("Weak cipher accepted" in i for i in a["issues"])


def test_assess_unreachable():
    a = tlsscan.assess(_normalised(ciphers=[], supported_protocols=[]))
    assert a["symbol"] == tlsscan.WARN
    assert a["label"] == "not reachable"
    assert any("unreachable" in i for i in a["issues"])


def test_run_markdown_has_verdict_and_sections(monkeypatch):
    monkeypatch.setattr(
        tlsscan, "available_engines", lambda: {"sslyze": False, "sslscan": True, "testssl": False}
    )
    monkeypatch.setitem(
        tlsscan._DRIVERS, "sslscan", lambda h, p, t: tlsscan._parse_sslscan_xml(SSLSCAN_XML)
    )
    args = argparse.Namespace(host="example.test", ports="443", engine="auto", timeout=1.0)
    finding = tlsscan.run(args)
    assert "Verdict" in finding.markdown
    assert "What's good" in finding.markdown
    assert "Issues to fix" in finding.markdown
    # SSLv3 enabled in the fixture -> insecure verdict
    assert tlsscan.BAD in finding.markdown


def test_xml_parser_rejects_entities():
    # A billion-laughs style DOCTYPE must be refused, not expanded.
    malicious = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE lolz [<!ENTITY lol 'lol'>]>"
        "<document><ssltest host='x' port='443'>&lol;</ssltest></document>"
    )
    with pytest.raises((ValueError, Exception)):  # noqa: B017 - defusedxml/expat raise different types
        tlsscan._xml_fromstring(malicious)
