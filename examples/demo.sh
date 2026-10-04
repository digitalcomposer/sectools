#!/usr/bin/env bash
#
# sectools demo: generate sample inputs and run every tool against them.
#
#   bash examples/demo.sh            # offline tools only (no internet needed)
#   bash examples/demo.sh --online   # also run the network tools (cvelookup, webrecon, certscan --host)
#
# Requires: sectools on PATH (activate your venv first). `pcaptriage` additionally
# needs tshark; the demo skips it with a note if tshark is missing.
set -euo pipefail

ONLINE=0
[[ "${1:-}" == "--online" ]] && ONLINE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$REPO_ROOT/tests/fixtures"

if ! command -v sectools >/dev/null 2>&1; then
  echo "error: 'sectools' not found on PATH. Activate your venv first:" >&2
  echo "  cd $REPO_ROOT && python -m venv .venv && . .venv/bin/activate && pip install -e ." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

section() { printf '\n\033[1;36m==== %s ====\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
section "doctor — environment & dependencies"
sectools doctor || true

# ---------------------------------------------------------------------------
section "verify — checksum of a file"
printf 'hello sectools' > sample.txt
MD5="$(sectools verify --file sample.txt --algorithm md5 --json | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["computed"])')"
sectools verify --file sample.txt --expected "$MD5" --algorithm md5

# ---------------------------------------------------------------------------
section "xorkey — recover a repeating-XOR key and decrypt"
python3 - <<'PY'
orig = bytes((i * 5) % 256 for i in range(400))
open("logo.jpg", "wb").write(orig)
key = bytes((i * 11) % 256 for i in range(32))
xor = lambda d, k: bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
open("logo.jpg_encrypted", "wb").write(xor(orig, key))
open("secret.txt_encrypted", "wb").write(xor(b"TOP SECRET: the flag is 42\n" * 3, key))
PY
sectools xorkey --plain logo.jpg --cipher logo.jpg_encrypted --key-length 32 \
  --decrypt secret.txt_encrypted --out-dir ./decrypted --key-json key.json
echo "-> decrypted/secret.txt:"; head -1 decrypted/secret.txt

# ---------------------------------------------------------------------------
section "dbexport — SQLite to filtered CSV"
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("logins.db")
c.executescript(
    "CREATE TABLE t_status(id INT, status TEXT);"
    "INSERT INTO t_status VALUES (1,'active'),(2,'locked');"
    "CREATE TABLE t_user(id INT, email TEXT, status_id INT);"
    "INSERT INTO t_user VALUES (3,'c@x.com',1),(1,'a@x.com',1),(2,'b@x.com',2);"
)
c.commit(); c.close()
PY
sectools dbexport --db logins.db --table t_user --columns "id,email" \
  --where "status_id = 1" --order-by "id ASC" --out active.csv
echo "-> active.csv:"; cat active.csv

# ---------------------------------------------------------------------------
section "mailscan — email manipulation indicators"
sectools mailscan --eml "$FIX/manipulated.eml"

# ---------------------------------------------------------------------------
section "certscan — analyse a certificate file"
sectools certscan --file "$FIX/sample_cert.pem"

# ---------------------------------------------------------------------------
section "pcaptriage — cleartext credentials in a capture"
if command -v tshark >/dev/null 2>&1; then
  sectools pcaptriage --pcap "$FIX/http_basic_auth.pcap" --credentials --json \
    | python3 -c 'import sys,json;print("credentials:",json.load(sys.stdin)["data"]["credentials"])'
else
  echo "skipped: tshark not installed (see docs/requirements.md)"
fi

# ---------------------------------------------------------------------------
if [[ "$ONLINE" -eq 1 ]]; then
  section "cvelookup — NVD lookup (online)"
  sectools cvelookup --cve CVE-2023-35078 | head -8

  section "webrecon — passive header check (online, example.com)"
  sectools webrecon --url https://example.com | head -8

  section "certscan --host (online, example.com)"
  sectools certscan --host example.com --ports 443
else
  printf '\n(tip: re-run with \033[1m--online\033[0m to also demo cvelookup, webrecon, and certscan --host)\n'
fi

printf '\n\033[1;32mDemo complete.\033[0m\n'
