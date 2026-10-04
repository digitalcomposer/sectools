"""Look up a CVE via the public NVD REST API 2.0 and summarise it.

Pulls the description, the CVSS base score and vector, references (advisory links),
and the published/modified dates. Network access is isolated in :func:`fetch` so the
parsing logic can be unit-tested against a saved response.

Example:
    sectools cvelookup --cve CVE-2023-35078 --json
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from typing import Any

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "cvelookup"
HELP = "look up a CVE on the NVD and summarise score, description, and references"

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = r"CVE-\d{4}-\d{4,}"


def fetch(cve_id: str, timeout: float = 20.0) -> dict[str, Any]:
    """Fetch the raw NVD JSON document for ``cve_id``."""
    url = f"{NVD_ENDPOINT}?cveId={cve_id}"
    request = urllib.request.Request(url, headers={"User-Agent": "sectools/0.1 (+cvelookup)"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed host
        return json.loads(response.read().decode("utf-8"))


def _best_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pick the most recent CVSS version available (v3.1 > v3.0 > v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0].get("cvssData", {})
            return {
                "version": cvss.get("version"),
                "base_score": cvss.get("baseScore"),
                "base_severity": cvss.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vector": cvss.get("vectorString"),
            }
    return {}


def parse_nvd_response(document: dict[str, Any]) -> dict[str, Any]:
    """Turn an NVD API response into a flat summary dict."""
    vulnerabilities = document.get("vulnerabilities") or []
    if not vulnerabilities:
        raise ValueError("no CVE found in response")
    cve = vulnerabilities[0]["cve"]

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )
    references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss": _best_cvss(cve.get("metrics", {})),
        "references": references,
    }


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cve", required=True, help="CVE identifier, e.g. CVE-2023-35078")
    parser.add_argument(
        "--from-file",
        help="parse a saved NVD JSON response instead of querying the network",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="network timeout (seconds)")


def run(args: argparse.Namespace) -> Finding:
    import re

    if not re.fullmatch(_CVE_RE, args.cve, flags=re.IGNORECASE):
        raise ValueError(f"not a CVE identifier: {args.cve!r}")

    if args.from_file:
        with open(args.from_file, encoding="utf-8") as handle:
            document = json.load(handle)
    else:
        try:
            document = fetch(args.cve.upper(), timeout=args.timeout)
        except urllib.error.URLError as exc:  # pragma: no cover - network dependent
            raise RuntimeError(f"NVD request failed: {exc}") from exc

    result = parse_nvd_response(document)
    cvss = result["cvss"]

    md = "\n\n".join(
        [
            report.heading(f"{result['id']}", 2),
            report.key_values(
                {
                    "CVSS version": cvss.get("version", "n/a"),
                    "Base score": cvss.get("base_score", "n/a"),
                    "Severity": cvss.get("base_severity", "n/a"),
                    "Vector": cvss.get("vector", "n/a"),
                    "Published": result["published"],
                }
            ),
            report.heading("Description", 3),
            result["description"],
            report.heading("References", 3),
            report.bullet_list(result["references"]) or "_none_",
        ]
    )

    return Finding(
        tool=NAME,
        summary=(
            f"{result['id']}: CVSS {cvss.get('base_score', 'n/a')} "
            f"({cvss.get('base_severity', 'n/a')})"
        ),
        data=result,
        markdown=md,
    )
