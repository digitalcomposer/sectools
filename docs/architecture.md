# Architecture

sectools is deliberately small and flat. The design goal is that each tool is
independently understandable and testable, while sharing one consistent interface
and output format.

## Layout

```
src/sectools/
├── __init__.py        # package version
├── __main__.py        # `python -m sectools`
├── cli.py             # builds the argparse CLI from the tool registry
├── core/              # shared, dependency-free building blocks
│   ├── checksums.py   # compute/verify file digests
│   ├── evidence.py    # Finding dataclass + evidence writer (JSON + Markdown)
│   └── report.py      # Markdown table/list/heading helpers
└── tools/             # one module per tool
    ├── __init__.py    # TOOLS registry
    ├── verify.py
    ├── xorkey.py
    ├── mailscan.py
    ├── webrecon.py
    ├── dbexport.py
    ├── cvelookup.py
    ├── pcaptriage.py
    └── certscan.py
```

## The tool contract

Every tool module exposes the same four names:

| Name | Purpose |
|---|---|
| `NAME` | the subcommand string |
| `HELP` | one-line help text |
| `add_arguments(parser)` | register the tool's CLI arguments |
| `run(args) -> Finding` | do the work and return a structured result |

`cli.py` iterates `TOOLS`, builds a subparser per tool, adds the shared output
options (`--json`, `--evidence`), and dispatches to `run`. Adding a tool therefore
means writing one module and appending it to the registry — nothing else changes.

## The Finding

`run` returns a `Finding` (see `core/evidence.py`) carrying:

- `summary` — a one-line human summary,
- `data` — the machine-readable result (what `--json` prints),
- `markdown` — an optional report-ready fragment,
- `warnings` — non-fatal flags (e.g. a checksum mismatch or a missing header).

This separation is what keeps "the machine does the mechanical part" distinct from
"the human interprets and writes up": the structured data and the draft fragment
are outputs you review, not conclusions the tool asserts.

## Dependencies and testability

The core and most tools use only the standard library. Heavier capabilities are
optional extras (`certs` → `cryptography`, `pcap` → `scapy`) with runtime
fallbacks (`certscan` falls back to the `openssl` CLI; `pcaptriage` shells out to
`tshark`). Network and subprocess calls live in small, isolated functions
(`fetch`, `get_peer_der`, `_run_fields`) so the parsing logic can be unit-tested
offline against fixtures.
