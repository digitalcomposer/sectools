"""Tiny helpers for emitting Markdown report fragments.

Every tool can turn its structured findings into a short Markdown snippet that a
human can paste into a report. Keeping the formatting in one place means the
tools stay consistent and the logic stays testable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence


def heading(text: str, level: int = 2) -> str:
    level = max(1, min(level, 6))
    return f"{'#' * level} {text}"


def bullet_list(items: Iterable[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _cell(value: object) -> str:
    """Render one table cell, escaping pipes so the table does not break."""
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """Render a GitHub-flavoured Markdown table."""
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows]
    return "\n".join([head, sep, *body])


def key_values(data: Mapping[str, object]) -> str:
    """Render a mapping as a two-column table (``Field`` / ``Value``)."""
    return table(["Field", "Value"], [(key, value) for key, value in data.items()])
