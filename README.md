# sectools

**A small, dependency-light toolkit of automated CLI utilities for everyday security analysis.**
One command, eight focused tools covering crypto, email and network forensics, certificates,
and data processing — each one turns a repetitive, mechanical analysis step into a single
reproducible command that can also emit machine-readable JSON and ready-to-paste evidence.

> ⚠️ **For educational use and authorized testing only.** The reconnaissance and scanning
> tools (`webrecon`, `certscan`) actively contact a target. Only run them against systems you
> own or have explicit, written permission to test.

[![CI](https://github.com/digitalcomposer/sectools/actions/workflows/ci.yml/badge.svg)](https://github.com/digitalcomposer/sectools/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Why

Security analysis is full of small, well-defined, repeatable steps: recover a repeating-XOR
key, pull apart an email's `Received` chain, export filtered rows from a SQLite database, look
up a CVE, triage a pcap, check a certificate's expiry. `sectools` automates exactly those
mechanical steps with a consistent interface, so the human can spend time on judgement and
reporting instead of boilerplate. The automated part ends where interpretation begins — most
tools output a structured *finding* plus a Markdown fragment for you to review and write up.

## Install

```bash
pip install sectools                 # core (standard library only)
pip install "sectools[certs]"        # richer X.509 parsing (cryptography)
pip install "sectools[pcap]"         # in-process pcap parsing (scapy)
```

From source:

```bash
git clone https://github.com/digitalcomposer/sectools
cd sectools
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Requirements

- **OS:** Linux, macOS, or Windows.
- **Python:** 3.10 or newer.
- **Core tools** (`verify`, `xorkey`, `mailscan`, `dbexport`, `cvelookup`,
  `webrecon`): **no extra tools** — standard library only. `cvelookup` and
  `webrecon` need **internet access** at runtime.
- **Two tools need an extra**, listed below.

| Tool | Needs | How it's satisfied |
|---|---|---|
| `pcaptriage` | **tshark** (Wireshark CLI) | required — install it (table below) |
| `certscan` | **cryptography** *or* **openssl** | `pip install "sectools[certs]"`, else falls back to the `openssl` CLI (preinstalled on macOS/Linux) |

Not sure what you have? Run the built-in check:

```bash
sectools doctor
```

It prints your OS, Python version, which dependencies are present/missing, what
each tool needs, and the exact install command for anything missing.

### Installing the external tools

**tshark** (only for `pcaptriage`):

| OS | Command |
|---|---|
| macOS (Homebrew) | `brew install wireshark` |
| Debian / Ubuntu | `sudo apt install tshark` |
| Fedora / RHEL | `sudo dnf install wireshark-cli` |
| Windows | `choco install wireshark` (or install Wireshark and add it to `PATH`) |

**openssl** (only for `certscan` *if* you did not install the `certs` extra — usually already present):

| OS | Command |
|---|---|
| macOS | preinstalled (or `brew install openssl`) |
| Debian / Ubuntu | `sudo apt install openssl` |
| Fedora / RHEL | `sudo dnf install openssl` |
| Windows | `choco install openssl` (or use Git for Windows' `openssl`) |

See [docs/requirements.md](docs/requirements.md) for the full details.

## Tools

| Command | What it does |
|---|---|
| `doctor` | Report OS, Python, and which optional/external dependencies are installed |
| `verify` | Compute / verify a file checksum (md5, sha1, sha256, sha512) |
| `xorkey` | Recover a repeating-XOR key from a known plaintext/ciphertext pair and decrypt files |
| `mailscan` | Analyse an `.eml`: headers, `Received` chain, and manipulation indicators |
| `webrecon` | Passively inspect a URL's security headers, cookie flags, and tech fingerprint |
| `dbexport` | Inspect a SQLite database and export a filtered, ordered CSV (read-only) |
| `cvelookup` | Look up a CVE on the NVD and summarise score, description, and references |
| `pcaptriage` | Triage a `.pcap`: protocol mix, cleartext credentials, handshake counts (via `tshark`) |
| `certscan` | Scan a host for TLS certificates or analyse certificate files (expiry, SANs, keys) |

Every command accepts `--json` (machine-readable output) and `--evidence DIR`
(write a timestamped JSON + Markdown record for your report).

## Examples

```bash
# Verify a download before you touch it
sectools verify --file sample.zip --expected be3c...6331 --algorithm md5

# Known-plaintext XOR: recover the key and decrypt the rest
sectools xorkey --plain logo.jpg --cipher logo.jpg_encrypted --key-length 32 \
    --decrypt report.pdf_encrypted --out-dir ./decrypted --key-json key.json

# Email forensics
sectools mailscan --eml message.eml --json

# SQLite -> filtered CSV (read-only)
sectools dbexport --db logins.db --table t_user \
    --columns "id,email" --where "status_id = 1" --order-by "id ASC" --out active.csv

# CVE summary
sectools cvelookup --cve CVE-2023-35078

# PCAP triage
sectools pcaptriage --pcap traffic.pcap --credentials --handshake-port 22

# Certificate scan (authorized targets only)
sectools certscan --host example.com --ports 443,8443
```

## Development

```bash
pip install -e ".[dev]"
pytest            # run the test suite
ruff check .      # lint
ruff format .     # format
mypy src          # type-check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[docs/architecture.md](docs/architecture.md) for how the pieces fit together.

## License

[MIT](LICENSE) © digitalcomposer
