"""Forensic analysis of an email message (.eml): headers, Received chain, anomalies.

This parses the raw message, reconstructs the ``Received`` hop chain with
timestamps, surfaces authentication results (SPF/DKIM/DMARC), and runs a set of
heuristic anomaly checks. The checks *flag* things for a human to judge; they do
not pronounce a message forged on their own.

Example:
    sectools mailscan --eml message.eml --json
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from email import message_from_bytes, utils
from email.message import Message
from pathlib import Path
from typing import TypedDict

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "mailscan"
HELP = "analyse an .eml message: headers, Received chain, and manipulation indicators"


class MailAnalysis(TypedDict):
    """Structured result of :func:`analyze`."""

    headers: dict[str, str | None]
    received_chain: list[dict[str, object]]
    hop_count: int
    date_header: str | None
    earliest_received_utc: str | None
    anomalies: list[str]

_RECEIVED_DATE_RE = re.compile(r";\s*(.+)$")
_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+)")


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed


def parse_received(header: str) -> dict[str, object]:
    """Parse one ``Received:`` header into its components."""
    hop: dict[str, object] = {"raw": header}
    for key in ("from", "by", "with", "for"):
        match = re.search(rf"\b{key}\s+(\S+)", header)
        if match:
            hop[key] = match.group(1)
    date_match = _RECEIVED_DATE_RE.search(header)
    if date_match:
        hop["date_raw"] = date_match.group(1).strip()
        parsed = _parse_date(date_match.group(1))
        hop["timestamp"] = parsed.isoformat() if parsed else None
    return hop


def _domain_of(address: str | None) -> str | None:
    if not address:
        return None
    match = _DOMAIN_RE.search(address)
    return match.group(1).lower() if match else None


def analyze(msg: Message) -> MailAnalysis:
    """Extract headers, the Received chain, and heuristic anomaly flags."""
    headers: dict[str, str | None] = {
        key: msg.get(key)
        for key in (
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "Return-Path",
            "Reply-To",
            "Authentication-Results",
            "DKIM-Signature",
            "Received-SPF",
            "X-Mailer",
            "User-Agent",
        )
        if msg.get(key)
    }

    received_raw = msg.get_all("Received") or []
    # Received headers are prepended on each hop, so index 0 is the latest hop.
    hops = [parse_received(h) for h in received_raw]

    anomalies: list[str] = []

    date_hdr = _parse_date(msg.get("Date"))
    hop_times: list[datetime] = []
    for h in hops:
        ts = h.get("timestamp")
        if isinstance(ts, str):
            hop_times.append(datetime.fromisoformat(ts))

    # 1) Date header far from the handling timestamps in the Received chain.
    if date_hdr and hop_times:
        earliest = min(hop_times)
        latest = max(hop_times)
        skew_before = (earliest - date_hdr).total_seconds()
        skew_after = (date_hdr - latest).total_seconds()
        if skew_before > 300:
            anomalies.append(
                f"Date header ({date_hdr.isoformat()}) is >5 min earlier than the "
                f"first server timestamp ({earliest.isoformat()})"
            )
        if skew_after > 300:
            anomalies.append(
                f"Date header ({date_hdr.isoformat()}) is >5 min later than the "
                f"last server timestamp ({latest.isoformat()})"
            )

    # 2) Received timestamps should increase as we walk from oldest to newest hop.
    ordered_oldest_first = list(reversed(hop_times))
    for a, b in zip(ordered_oldest_first, ordered_oldest_first[1:], strict=False):
        if b < a:
            anomalies.append(
                f"Non-monotonic Received timestamps: {a.isoformat()} followed by "
                f"{b.isoformat()} (hops may have been edited)"
            )
            break

    # 3) Message-ID domain not matching the From domain.
    from_domain = _domain_of(msg.get("From"))
    mid_domain = _domain_of(msg.get("Message-ID"))
    if from_domain and mid_domain and from_domain != mid_domain:
        anomalies.append(
            f"Message-ID domain ({mid_domain}) differs from From domain ({from_domain})"
        )

    # 4) No authentication evidence at all.
    if not any(k in headers for k in ("Authentication-Results", "DKIM-Signature", "Received-SPF")):
        anomalies.append("No SPF/DKIM/DMARC authentication headers present")

    return {
        "headers": headers,
        "received_chain": hops,
        "hop_count": len(hops),
        "date_header": date_hdr.isoformat() if date_hdr else None,
        "earliest_received_utc": (
            min(hop_times).astimezone(timezone.utc).isoformat() if hop_times else None
        ),
        "anomalies": anomalies,
    }


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--eml", required=True, help="path to the raw .eml message")


def run(args: argparse.Namespace) -> Finding:
    raw = Path(args.eml).read_bytes()
    msg = message_from_bytes(raw)
    result = analyze(msg)

    anomalies = result["anomalies"]
    md_parts = [
        report.heading("Email analysis", 2),
        report.key_values(
            {
                "From": result["headers"].get("From"),
                "Date header": result["date_header"],
                "Hops (Received)": result["hop_count"],
                "Indicators found": len(anomalies),
            }
        ),
    ]
    if anomalies:
        md_parts.append(report.heading("Manipulation indicators", 3))
        md_parts.append(report.bullet_list(anomalies))
    md = "\n\n".join(md_parts)

    return Finding(
        tool=NAME,
        summary=f"{result['hop_count']} hop(s), {len(anomalies)} indicator(s) flagged",
        data=dict(result),
        markdown=md,
        warnings=list(anomalies),
    )
