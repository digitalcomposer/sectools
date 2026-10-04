"""Triage a packet capture: protocol mix, top talkers, cleartext credentials.

Built on top of the ``tshark`` CLI (part of Wireshark), which is far more robust
across Python versions than in-process pcap parsers. If ``tshark`` is not on the
PATH the tool explains how to install it.

Example:
    sectools pcaptriage --pcap traffic.pcap --credentials --handshake-port 22
"""

from __future__ import annotations

import argparse
import base64
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "pcaptriage"
HELP = "triage a .pcap: protocol mix, top talkers, cleartext credentials, handshake counts"


def find_tshark() -> str | None:
    return shutil.which("tshark")


def _run_fields(pcap: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    """Run ``tshark -T fields`` and return rows split on tab."""
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError(
            "tshark not found. Install Wireshark/tshark "
            "(macOS: `brew install wireshark`, Debian/Ubuntu: `apt install tshark`)."
        )
    argv = [tshark, "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for field in fields:
        argv += ["-e", field]
    argv += ["-E", "separator=/t"]
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, check=True
    ).stdout.decode("utf-8", "replace")
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def decode_basic_auth(value: str) -> dict[str, str] | None:
    """Decode an HTTP ``Authorization: Basic <b64>`` value into user/password."""
    token = value.split(" ", 1)[-1].strip()
    try:
        decoded = base64.b64decode(token).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return None
    if ":" not in decoded:
        return None
    user, password = decoded.split(":", 1)
    return {"scheme": "http-basic", "username": user, "password": password}


def extract_credentials(pcap: str) -> list[dict[str, Any]]:
    """Pull cleartext credentials from common plaintext protocols."""
    creds: list[dict[str, Any]] = []

    for (auth,) in _run_fields(pcap, "http.authorization", ["http.authorization"]):
        parsed = decode_basic_auth(auth)
        if parsed:
            creds.append(parsed)

    # HTTP form POSTs (application/x-www-form-urlencoded).
    for row in _run_fields(
        pcap,
        'http.request.method == "POST" && urlencoded-form',
        ["http.host", "urlencoded-form.key", "urlencoded-form.value"],
    ):
        host = row[0] if row else ""
        keys = row[1].split(",") if len(row) > 1 else []
        values = row[2].split(",") if len(row) > 2 else []
        form = dict(zip(keys, values, strict=False))
        if form:
            creds.append({"scheme": "http-form", "host": host, "fields": form})

    # FTP / plaintext USER + PASS.
    ftp = _run_fields(
        pcap,
        "ftp.request.command in {USER PASS}",
        ["ftp.request.command", "ftp.request.arg"],
    )
    user: str | None = None
    for row in ftp:
        command = row[0] if len(row) > 0 else ""
        arg = row[1] if len(row) > 1 else ""
        if command == "USER":
            user = arg
        elif command == "PASS":
            creds.append({"scheme": "ftp", "username": user, "password": arg})
    return creds


def count_handshakes(pcap: str, port: int) -> tuple[int, str]:
    """Count TCP connection attempts (SYN, no ACK) to ``port``; return (count, filter)."""
    display_filter = f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == {port}"
    rows = _run_fields(pcap, display_filter, ["frame.number"])
    return len(rows), display_filter


def protocol_hierarchy(pcap: str) -> str:
    """Return tshark's protocol hierarchy statistics as text."""
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("tshark not found")
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [tshark, "-r", pcap, "-q", "-z", "io,phs"], capture_output=True, check=True
    ).stdout.decode("utf-8", "replace")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pcap", required=True, help="path to the capture file")
    parser.add_argument(
        "--credentials", action="store_true", help="search for cleartext credentials"
    )
    parser.add_argument(
        "--handshake-port", type=int, help="count TCP SYN connection attempts to this port"
    )
    parser.add_argument("--phs", action="store_true", help="include protocol hierarchy stats")


def run(args: argparse.Namespace) -> Finding:
    pcap = str(Path(args.pcap))
    data: dict[str, Any] = {}
    warnings: list[str] = []
    md_parts = [report.heading("PCAP triage", 2)]

    if args.credentials:
        creds = extract_credentials(pcap)
        data["credentials"] = creds
        if creds:
            warnings.append(f"{len(creds)} cleartext credential record(s) found")
        md_parts.append(report.heading("Cleartext credentials", 3))
        md_parts.append(f"Found {len(creds)} record(s).")

    if args.handshake_port is not None:
        count, flt = count_handshakes(pcap, args.handshake_port)
        data["handshakes"] = {"port": args.handshake_port, "count": count, "filter": flt}
        md_parts.append(report.heading(f"Handshakes on port {args.handshake_port}", 3))
        md_parts.append(
            report.key_values({"Connection attempts (SYN)": count, "Wireshark filter": flt})
        )

    if args.phs:
        data["protocol_hierarchy"] = protocol_hierarchy(pcap)

    summary_bits = []
    if "credentials" in data:
        summary_bits.append(f"{len(data['credentials'])} credential record(s)")
    if "handshakes" in data:
        summary_bits.append(f"{data['handshakes']['count']} handshake(s)")
    summary = ", ".join(summary_bits) or "triage complete"

    return Finding(
        tool=NAME,
        summary=summary,
        data=data,
        markdown="\n\n".join(md_parts),
        warnings=warnings,
    )
