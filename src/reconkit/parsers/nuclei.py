"""Parser for ``nuclei -jsonl`` output.

Nuclei already assigns a severity per template (``info.severity``), so each JSONL
record maps almost one-to-one onto a :class:`~reconkit.models.Finding`. reconkit
adds no new verdicts here; it normalises the fields into the shared model so a
nuclei scan merges cleanly with nmap and httpx findings in one report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO, Union

from ..models import Finding

Source = Union[str, Path, IO[str], IO[bytes]]

KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")

#: Classification fields that carry CVE / CWE identifiers inside ``info``.
_REFERENCE_FIELDS = ("reference", "references", "cve", "cwe", "cve-id", "cwe-id")


def _as_list(value: object) -> list[str]:
    """Normalise a field that may be a list, a single string, or ``None``."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, (str, int)):
        return [str(value)]
    return []


def _read_text(source: Source) -> str:
    if isinstance(source, (str, Path)):
        return Path(source).read_text(encoding="utf-8", errors="replace")
    data = source.read()  # type: ignore[union-attr]
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def parse_nuclei_jsonl(source: Source) -> list[Finding]:
    """Parse nuclei JSONL output into :class:`Finding` objects.

    Blank lines, comment lines and malformed records are skipped, matching the
    behaviour of the other parsers.
    """
    findings: list[Finding] = []

    for line in _read_text(source).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        template_id = str(
            record.get("template-id") or record.get("templateID") or "unknown-template"
        )
        info = record.get("info")
        if not isinstance(info, dict):
            info = {}

        severity = str(info.get("severity") or "info").lower()
        if severity not in KNOWN_SEVERITIES:
            severity = "info"

        asset = str(
            record.get("matched-at")
            or record.get("matched")
            or record.get("host")
            or "unknown-asset"
        )

        evidence_bits = []
        matcher = record.get("matcher-name") or record.get("matcher")
        if matcher:
            evidence_bits.append("matcher: {}".format(matcher))
        evidence_bits.append("type: {}".format(record.get("type") or "unknown"))
        extracted = _as_list(record.get("extracted-results"))
        if extracted:
            evidence_bits.append("extracted: {}".format(", ".join(extracted[:5])))

        references = _as_list(info.get("reference"))
        classification = info.get("classification")
        if isinstance(classification, dict):
            for field in ("cve-id", "cve", "cwe-id", "cwe"):
                references.extend(ref for ref in _as_list(classification.get(field)))

        findings.append(
            Finding(
                check_id=template_id,
                title=str(info.get("name") or template_id),
                severity=severity,
                asset=asset,
                description=str(info.get("description") or "").strip()
                or "Matched by nuclei template `{}`.".format(template_id),
                evidence="; ".join(evidence_bits) or "matched-at: {}".format(asset),
                remediation=str(info.get("remediation") or "").strip()
                or "Review the matched template and apply the vendor-recommended fix.",
                references=references,
            )
        )

    return findings
