from __future__ import annotations

import json

from sectools.cli import main
from sectools.tools import cvelookup


def test_parse_nvd_response(fixtures):
    document = json.loads((fixtures / "nvd_sample.json").read_text())
    result = cvelookup.parse_nvd_response(document)
    assert result["id"] == "CVE-2023-00000"
    assert result["cvss"]["base_score"] == 9.8
    assert result["cvss"]["base_severity"] == "CRITICAL"
    assert result["description"].startswith("A sample authentication bypass")
    assert "https://vendor.example/advisory/001" in result["references"]


def test_cli_from_file_offline(fixtures, capsys):
    rc = main(
        [
            "cvelookup",
            "--cve",
            "CVE-2023-00000",
            "--from-file",
            str(fixtures / "nvd_sample.json"),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["cvss"]["base_score"] == 9.8
