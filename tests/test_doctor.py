from __future__ import annotations

import json

from sectools.cli import main
from sectools.tools import doctor


def test_check_dependencies_keys():
    deps = doctor.check_dependencies()
    assert set(deps) == {
        "tshark",
        "openssl",
        "cryptography (Python)",
        "sslyze (Python)",
        "sslscan",
        "testssl.sh",
    }
    assert all(isinstance(v, bool) for v in deps.values())


def test_every_tool_has_a_requirement_entry():
    from sectools.tools import TOOLS

    documented = set(doctor.TOOL_REQUIREMENTS)
    actual = {t.NAME for t in TOOLS if t.NAME != "doctor"}
    assert actual <= documented, f"undocumented tools: {actual - documented}"


def test_cli_doctor_json_reports_missing(monkeypatch, capsys):
    # Force a known state so the assertion is deterministic.
    monkeypatch.setattr(
        doctor,
        "check_dependencies",
        lambda: {"tshark": True, "openssl": True, "cryptography (Python)": False},
    )
    rc = main(["doctor", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["missing"] == ["cryptography (Python)"]
    assert payload["data"]["dependencies"]["tshark"] is True
