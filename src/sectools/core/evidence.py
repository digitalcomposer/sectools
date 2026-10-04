"""Structured result and evidence handling shared by every tool.

Each tool returns a :class:`Finding`. The CLI decides how to present it: as
human-readable text, as JSON (``--json``), or written to an evidence directory
(``--evidence DIR``) as a timestamped JSON file plus a Markdown fragment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """The result of running one tool.

    ``data`` holds the machine-readable result, ``summary`` is a one-line human
    summary, and ``markdown`` is an optional report-ready fragment. ``warnings``
    collects non-fatal issues (e.g. a checksum mismatch) worth surfacing.
    """

    tool: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    markdown: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "summary": self.summary,
            "data": self.data,
            "warnings": self.warnings,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str, sort_keys=False)


def write_evidence(finding: Finding, directory: str | Path) -> list[Path]:
    """Persist ``finding`` into ``directory`` and return the files written.

    Writes ``<tool>-<timestamp>.json`` always, and ``<tool>-<timestamp>.md`` when
    the finding carries a Markdown fragment. The directory is created if needed.
    """
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    written: list[Path] = []

    json_path = out / f"{finding.tool}-{stamp}.json"
    json_path.write_text(finding.to_json() + "\n", encoding="utf-8")
    written.append(json_path)

    if finding.markdown:
        md_path = out / f"{finding.tool}-{stamp}.md"
        md_path.write_text(finding.markdown.rstrip() + "\n", encoding="utf-8")
        written.append(md_path)

    return written
