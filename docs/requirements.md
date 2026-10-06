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
| `tlsscan` | **sslscan** *or* **testssl.sh** *(fallbacks)* | **`[tls]` → sslyze** | **yes** (`--host`) | Uses `sslyze` if installed, else the `sslscan` or `testssl.sh` CLI; needs at least one |

"Standard library only" means nothing beyond Python itself is required.

## Python extras

```bash
pip install sectools                 # core — everything except pcaptriage/certscan/tlsscan extras
pip install "sectools[certs]"        # cryptography, for richer certscan parsing
pip install "sectools[pcap]"         # scapy, an alternative pcap engine
pip install "sectools[tls]"          # sslyze, the preferred tlsscan engine
pip install "sectools[certs,pcap,tls]"  # everything
```

If you install `sectools[certs]`, `certscan` does **not** need the `openssl` CLI.
If you do not, `certscan` automatically falls back to `openssl`, which is
preinstalled on macOS and most Linux distributions.

`pcaptriage` uses the `tshark` CLI by default and does not require the `pcap`
extra; the extra only adds scapy as an alternative in-process engine.

`tlsscan` prefers the `sslyze` package (`sectools[tls]`, structured output,
cross-platform). Without it, it falls back to the `sslscan` or `testssl.sh` CLI —
whichever is installed. At least one of the three is required; `sectools doctor`
shows which you have. Pick a specific engine with `--engine {sslyze,sslscan,testssl}`.

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

## Installing a TLS scanner (for `tlsscan`, only without the `tls` extra)

Any **one** of these is enough; `sectools doctor` shows which you have.

**sslscan:**

| OS | Command |
|---|---|
| macOS (Homebrew) | `brew install sslscan` |
| Debian / Ubuntu | `sudo apt install sslscan` |
| Fedora / RHEL | `sudo dnf install sslscan` |
| Arch | `sudo pacman -S sslscan` |
| Windows (Chocolatey) | `choco install sslscan` |

**testssl.sh:**

| OS | Command |
|---|---|
| macOS (Homebrew) | `brew install testssl` |
| Debian / Ubuntu | `sudo apt install testssl.sh` |
| Fedora / RHEL | `sudo dnf install testssl` |
| Windows | Run under WSL or Git Bash: `git clone https://github.com/drwetter/testssl.sh` |

`testssl.sh` is the most thorough but also the slowest; raise `--timeout` for busy
hosts. For structured, cross-platform output without a CLI, prefer `sectools[tls]`
(sslyze) instead.
