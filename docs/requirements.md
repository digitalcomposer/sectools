# Requirements & dependencies

## Supported platforms

sectools is pure Python and runs on **Linux, macOS, and Windows** with
**Python 3.10 or newer**. The only platform-specific pieces are two external
command-line tools used by two of the commands (see below).

Run `sectools doctor` at any time to see your environment and what, if anything,
is missing.

## What each tool needs

| Tool | External tool | Python extra | Network | Notes |
|---|---|---|---|---|
| `doctor` | — | — | no | Self-diagnosis |
| `verify` | — | — | no | Standard library only |
| `xorkey` | — | — | no | Standard library only |
| `mailscan` | — | — | no | Standard library only |
| `dbexport` | — | — | no | Standard library only (SQLite is built in) |
| `cvelookup` | — | — | **yes** | Queries the NVD REST API (or use `--from-file`) |
| `webrecon` | — | — | **yes** | Single GET to the target |
| `pcaptriage` | **tshark** | *(or `[pcap]` → scapy)* | no | tshark is the default engine |
| `certscan` | **openssl** *(fallback)* | **`[certs]` → cryptography** | only with `--host` | Parses with `cryptography` if installed, else the `openssl` CLI |

"Standard library only" means nothing beyond Python itself is required.

## Python extras

```bash
pip install sectools                 # core — everything except pcaptriage/certscan extras
pip install "sectools[certs]"        # cryptography, for richer certscan parsing
pip install "sectools[pcap]"         # scapy, an alternative pcap engine
pip install "sectools[certs,pcap]"   # both
```

If you install `sectools[certs]`, `certscan` does **not** need the `openssl` CLI.
If you do not, `certscan` automatically falls back to `openssl`, which is
preinstalled on macOS and most Linux distributions.

`pcaptriage` uses the `tshark` CLI by default and does not require the `pcap`
extra; the extra only adds scapy as an alternative in-process engine.

## Installing tshark (for `pcaptriage`)

| OS | Command |
|---|---|
| macOS (Homebrew) | `brew install wireshark` |
| Debian / Ubuntu | `sudo apt install tshark` |
| Fedora / RHEL | `sudo dnf install wireshark-cli` |
| Arch | `sudo pacman -S wireshark-cli` |
| Windows (Chocolatey) | `choco install wireshark` |
| Windows (winget) | `winget install WiresharkFoundation.Wireshark` |
| Windows (manual) | Install [Wireshark](https://www.wireshark.org/download.html); it bundles `tshark`. Add its folder to `PATH`. |

On Debian/Ubuntu the installer asks whether non-superusers may capture packets.
sectools only *reads* existing capture files, so either answer is fine. For an
unattended install: `sudo DEBIAN_FRONTEND=noninteractive apt install -y tshark`.

Verify it is on your `PATH`:

```bash
tshark --version
```

## Installing openssl (for `certscan`, only without the `certs` extra)

| OS | Command |
|---|---|
| macOS | preinstalled (or `brew install openssl`) |
| Debian / Ubuntu | `sudo apt install openssl` |
| Fedora / RHEL | `sudo dnf install openssl` |
| Windows (Chocolatey) | `choco install openssl` |
| Windows (Git) | Git for Windows ships an `openssl` you can add to `PATH` |

Verify:

```bash
openssl version
```
