from __future__ import annotations

import json
from email import message_from_bytes

from sectools.cli import main
from sectools.tools import mailscan


def test_parse_received_extracts_fields():
    header = (
        "from mail.example.com (mail.example.com [198.51.100.7]) "
        "by relay.receiver.net with ESMTP id XYZ789; "
        "Sat, 27 May 2023 11:05:00 +0000"
    )
    hop = mailscan.parse_received(header)
    assert hop["from"] == "mail.example.com"
    assert hop["by"] == "relay.receiver.net"
    assert hop["timestamp"].startswith("2023-05-27T11:05:00")


def test_analyze_flags_manipulation(fixtures):
    msg = message_from_bytes((fixtures / "manipulated.eml").read_bytes())
    result = mailscan.analyze(msg)
    assert result["hop_count"] == 2
    anomalies = " ".join(result["anomalies"]).lower()
    assert "date header" in anomalies  # Date far from Received timestamps
    assert "message-id domain" in anomalies  # domain mismatch
    assert "authentication" in anomalies  # no SPF/DKIM


def test_cli_run_and_evidence(fixtures, tmp_path, capsys):
    ev = tmp_path / "ev"
    rc = main(
        ["mailscan", "--eml", str(fixtures / "manipulated.eml"), "--json", "--evidence", str(ev)]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "mailscan"
    assert len(payload["data"]["anomalies"]) == 3
    # --evidence wrote a JSON + Markdown record
    written = list(ev.glob("mailscan-*"))
    assert {p.suffix for p in written} == {".json", ".md"}
