"""Report which optional dependencies are available and what each tool needs.

Run ``sectools doctor`` to see, at a glance, whether the external tools some
commands rely on (``tshark``, ``openssl``, the ``cryptography`` package) are
installed, and how to install the missing ones on your OS.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import sys

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "doctor"
HELP = "check which optional/external dependencies are installed and how to get them"

# Install hints per dependency and per OS family.
INSTALL_HINTS: dict[str, dict[str, str]] = {
    "tshark": {
        "macOS": "brew install wireshark",
        "Debian/Ubuntu": "sudo apt install tshark",
        "Fedora/RHEL": "sudo dnf install wireshark-cli",
        "Windows": "choco install wireshark  (or install Wireshark and add it to PATH)",
    },
    "openssl": {
        "macOS": "preinstalled (or: brew install openssl)",
        "Debian/Ubuntu": "sudo apt install openssl",
        "Fedora/RHEL": "sudo dnf install openssl",
        "Windows": "choco install openssl  (or use Git for Windows' openssl)",
    },
    "cryptography (Python)": {
        "all": 'pip install "sectools[certs]"',
    },
    "sslyze (Python)": {
        "all": 'pip install "sectools[tls]"',
    },
    "sslscan": {
        "macOS": "brew install sslscan",
        "Debian/Ubuntu": "sudo apt install sslscan",
        "Fedora/RHEL": "sudo dnf install sslscan",
        "Windows": "choco install sslscan  (or download a release build)",
    },
    "testssl.sh": {
        "macOS": "brew install testssl",
        "Debian/Ubuntu": "sudo apt install testssl.sh",
        "Fedora/RHEL": "sudo dnf install testssl",
        "Windows": "run under WSL / Git Bash (git clone drwetter/testssl.sh)",
    },
}


def _module_available(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def check_dependencies() -> dict[str, bool]:
    """Return availability of each external/optional dependency."""
    return {
        "tshark": shutil.which("tshark") is not None,
        "openssl": shutil.which("openssl") is not None,
        "cryptography (Python)": _module_available("cryptography"),
        "sslyze (Python)": _module_available("sslyze"),
        "sslscan": shutil.which("sslscan") is not None,
        "testssl.sh": shutil.which("testssl.sh") is not None or shutil.which("testssl") is not None,
    }


# Which tools need what. "—" means standard library only.
TOOL_REQUIREMENTS: dict[str, str] = {
    "verify": "—",
    "xorkey": "—",
    "mailscan": "—",
    "dbexport": "—",
    "cvelookup": "network (NVD)",
    "webrecon": "network",
    "pcaptriage": "tshark",
    "certscan": "cryptography (Python) OR openssl",
    "tlsscan": "sslyze (Python) OR sslscan OR testssl.sh",
}


def add_arguments(parser: argparse.ArgumentParser) -> None:  # noqa: ARG001 - no options
    pass


def run(args: argparse.Namespace) -> Finding:  # noqa: ARG001 - no options
    deps = check_dependencies()
    os_family = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}.get(
        platform.system(), platform.system()
    )

    dep_rows = [(name, "yes" if present else "MISSING") for name, present in deps.items()]
    missing = [name for name, present in deps.items() if not present]

    md_parts = [
        report.heading("Environment", 2),
        report.key_values(
            {
                "Python": platform.python_version(),
                "OS": f"{os_family} ({platform.machine()})",
            }
        ),
        report.heading("Optional / external dependencies", 3),
        report.table(["Dependency", "Status"], dep_rows),
        report.heading("Per-tool requirements", 3),
        report.table(["Tool", "Needs"], list(TOOL_REQUIREMENTS.items())),
    ]

    if missing:
        hint_lines = []
        for dep in missing:
            hints = INSTALL_HINTS.get(dep, {})
            cmd = hints.get(os_family) or hints.get("all") or "see project README"
            hint_lines.append(f"`{dep}` → {cmd}")
        md_parts.append(report.heading("How to install what's missing", 3))
        md_parts.append(report.bullet_list(hint_lines))

    summary = (
        "all optional dependencies present"
        if not missing
        else f"{len(missing)} optional dependency/ies missing: {', '.join(missing)}"
    )
    return Finding(
        tool=NAME,
        summary=summary,
        data={
            "python": platform.python_version(),
            "os": os_family,
            "machine": platform.machine(),
            "executable": sys.executable,
            "dependencies": deps,
            "tool_requirements": TOOL_REQUIREMENTS,
            "missing": missing,
        },
        markdown="\n\n".join(md_parts),
        warnings=[f"missing optional dependency: {m}" for m in missing],
    )
