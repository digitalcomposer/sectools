from __future__ import annotations

import pytest

from sectools.cli import build_parser, main


def test_every_tool_registers_a_subcommand():
    parser = build_parser()
    # Argparse stores subparsers in the first (and only) subparsers action.
    actions = [a for a in parser._actions if a.dest == "command"]
    assert actions, "no subcommand group found"
    names = set(actions[0].choices)
    assert {
        "doctor",
        "verify",
        "xorkey",
        "mailscan",
        "webrecon",
        "dbexport",
        "cvelookup",
        "pcaptriage",
        "certscan",
    } <= names


def test_verify_subcommand(tmp_path, capsys):
    f = tmp_path / "f.bin"
    f.write_bytes(b"abc")
    rc = main(["verify", "--file", str(f), "--algorithm", "md5"])
    assert rc == 0
    assert "md5" in capsys.readouterr().out


def test_unknown_command_exits():
    with pytest.raises(SystemExit):
        main(["does-not-exist"])


def test_missing_file_returns_error_code(capsys):
    rc = main(["verify", "--file", "/no/such/file", "--algorithm", "md5"])
    assert rc == 2
    assert "error:" in capsys.readouterr().err
