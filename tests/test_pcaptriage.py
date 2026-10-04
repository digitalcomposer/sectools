from __future__ import annotations

import base64
import json

import pytest

from sectools.cli import main
from sectools.tools import pcaptriage

_has_tshark = pcaptriage.find_tshark() is not None


def test_decode_basic_auth():
    token = base64.b64encode(b"alice:s3cret").decode()
    parsed = pcaptriage.decode_basic_auth(f"Basic {token}")
    assert parsed == {"scheme": "http-basic", "username": "alice", "password": "s3cret"}


def test_decode_basic_auth_rejects_garbage():
    assert pcaptriage.decode_basic_auth("Basic not-base64!!") is None
    token = base64.b64encode(b"no-colon-here").decode()
    assert pcaptriage.decode_basic_auth(f"Basic {token}") is None


def _fake_run_fields_factory():
    """Return a stand-in for tshark that answers by display filter."""
    token = base64.b64encode(b"alice:s3cret").decode()

    def fake(pcap, display_filter, fields):
        if "http.authorization" in display_filter:
            return [[f"Basic {token}"]]
        if "urlencoded-form" in display_filter:
            return [["example.com", "user,pass", "bob,hunter2"]]
        if "ftp.request.command" in display_filter:
            return [["USER", "carol"], ["PASS", "pw123"]]
        if "tcp.flags.syn" in display_filter:
            return [["1"], ["2"], ["3"]]  # three SYNs
        return []

    return fake


def test_extract_credentials_all_schemes(monkeypatch):
    monkeypatch.setattr(pcaptriage, "_run_fields", _fake_run_fields_factory())
    creds = pcaptriage.extract_credentials("x.pcap")
    schemes = {c["scheme"] for c in creds}
    assert schemes == {"http-basic", "http-form", "ftp"}
    basic = next(c for c in creds if c["scheme"] == "http-basic")
    assert basic == {"scheme": "http-basic", "username": "alice", "password": "s3cret"}
    ftp = next(c for c in creds if c["scheme"] == "ftp")
    assert ftp["username"] == "carol" and ftp["password"] == "pw123"


def test_cli_run_credentials_and_handshakes(monkeypatch, tmp_path, capsys):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")  # dummy; _run_fields is mocked
    monkeypatch.setattr(pcaptriage, "_run_fields", _fake_run_fields_factory())
    rc = main(
        ["pcaptriage", "--pcap", str(pcap), "--credentials", "--handshake-port", "22", "--json"]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["data"]["credentials"]) == 3
    assert payload["data"]["handshakes"]["count"] == 3
    assert payload["data"]["handshakes"]["port"] == 22


@pytest.mark.skipif(not _has_tshark, reason="needs the tshark CLI")
def test_integration_real_tshark_filters(fixtures):
    """Run the real tshark filters against a fixture pcap.

    This catches invalid display-filter syntax that the mocked unit tests cannot
    (e.g. a filter that makes tshark exit non-zero).
    """
    pcap = str(fixtures / "http_basic_auth.pcap")
    creds = pcaptriage.extract_credentials(pcap)  # exercises http + form + ftp filters
    basic = [c for c in creds if c["scheme"] == "http-basic"]
    assert basic and basic[0]["username"] == "alice"

    count, flt = pcaptriage.count_handshakes(pcap, 80)
    assert "tcp.flags.syn" in flt
    assert isinstance(count, int)
