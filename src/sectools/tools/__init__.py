"""Tool registry.

Each tool is a module exposing ``NAME``, ``HELP``, ``add_arguments(parser)`` and
``run(args) -> Finding``. The CLI iterates over :data:`TOOLS` to build its
subcommands, so adding a tool is just appending it here.
"""

from __future__ import annotations

from sectools.tools import (
    certscan,
    cvelookup,
    dbexport,
    doctor,
    mailscan,
    pcaptriage,
    verify,
    webrecon,
    xorkey,
)

TOOLS = [
    doctor,
    verify,
    xorkey,
    mailscan,
    webrecon,
    dbexport,
    cvelookup,
    pcaptriage,
    certscan,
]

__all__ = ["TOOLS"]
