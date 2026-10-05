"""Renderers: turn a :class:`Report` into Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from string import Template

from . import __version__
from .models import Finding, Report, SEVERITIES

TEMPLATE_PATH = Path(__file__).with_name("templates") / "report.md.tmpl"

DISCLAIMER_SHORT = (
    "**Confidential.** This report is prepared for the named client only and describes the security "
    "posture of the systems in scope at the time of testing. It must not be redistributed without "
    "written consent."
)

DISCLAIMER_FULL = """\
This document contains information that could be used to attack the systems described. It is issued
solely to the client named above and is confidential.

The assessment reflects the state of the in-scope systems during the testing window only. Security
posture changes continuously; findings may no longer be accurate after remediation or after
infrastructure changes. Findings are derived from automated analysis of scan output and require
human validation before they are treated as confirmed vulnerabilities.

Testing was performed within the agreed scope and rules of engagement. No action was taken to
modify, delete or exfiltrate data, and no denial-of-service condition was induced.

The tooling used to generate this document is provided as-is, without warranty of any kind. The
authors accept no liability for use outside an authorised engagement.
"""

METHODOLOGY = """\
Data was collected with standard, non-destructive discovery tooling and then normalised and analysed
by `reconkit`.

**Collection**

* TCP port and service discovery: `nmap -sV -sC`
* HTTP probing, fingerprinting and technology detection: `httpx -jsonl`

**Analysis**

* Port exposure rules (data-driven, see `rules/default.json`)
* Service fingerprint review against script output from nmap NSE
* Web surface review: management interfaces, non-production hostnames, cleartext transport,
  sensitive paths

**Limitations**

* Version fingerprints are recorded for manual review; reconkit does not claim CVE matches.
* No authenticated testing was performed unless stated in the scope above.
* Business-logic, client-side and social-engineering classes of issue are out of scope for automated
  analysis.
* Automated checks produce both false positives and false negatives. Every finding below should be
  validated manually before it is reported to a system owner.
"""


def md_escape(value: str) -> str:
    """Escape pipes and newlines so values survive inside a Markdown table cell."""
    return value.replace("|", "\\|").replace("\n", " ").strip()


def _finding_block(index: int, finding: Finding) -> str:
    lines = [
        "### {}. {} — {}".format(index, finding.severity.upper(), finding.title),
        "",
        "| | |",
        "|---|---|",
        "| **Check ID** | `{}` |".format(finding.check_id),
        "| **Severity** | {} |".format(finding.severity.capitalize()),
        "| **Affected asset** | `{}` |".format(md_escape(finding.asset)),
        "",
    ]
    if finding.description:
        lines += ["**Description**", "", finding.description.strip(), ""]
    if finding.evidence:
        lines += ["**Evidence**", "", "```", finding.evidence.strip(), "```", ""]
    if finding.remediation:
        lines += ["**Remediation**", "", finding.remediation.strip(), ""]
    if finding.references:
        lines += ["**References**", ""]
        lines += ["- {}".format(ref) for ref in finding.references]
        lines += [""]
    return "\n".join(lines)


def _exec_summary(report: Report) -> str:
    counts = report.counts_by_severity()
    total = len(report.findings)
    hosts_up = len(report.hosts)
    open_ports = sum(len(h.open_ports) for h in report.hosts)

    if total == 0:
        headline = (
            "No findings were raised by the automated checks. This does **not** mean the environment "
            "is free of vulnerabilities; it means nothing matched the rule set. Treat the absence of "
            "findings as a prompt for manual testing, not as a clean bill of health."
        )
    else:
        headline = (
            "{total} finding(s) were raised across {hosts} host(s) and {targets} HTTP endpoint(s). "
            "The highest severity observed is **{top}**. Address critical and high findings first: "
            "they represent reachable paths to credential theft or remote code execution."
        ).format(
            total=total,
            hosts=hosts_up,
            targets=len(report.web_targets),
            top=report.findings[0].severity.upper(),
        )

    table = [
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in SEVERITIES:
        table.append("| {} | {} |".format(severity.capitalize(), counts.get(severity, 0)))
    table.append("| **Total** | **{}** |".format(total))

    assets = [
        "",
        "**Observed attack surface**",
        "",
        "- Hosts reported up: **{}**".format(hosts_up),
        "- Open ports: **{}**".format(open_ports),
        "- HTTP endpoints probed: **{}**".format(len(report.web_targets)),
    ]

    top = [f for f in report.findings if f.severity in ("critical", "high")][:5]
    if top:
        assets += ["", "**Priority items**", ""]
        assets += [
            "{}. `{}` — {} ({})".format(i, f.asset, f.title, f.severity)
            for i, f in enumerate(top, 1)
        ]

    return "\n".join([headline, "", *table, *assets])


def _scope(report: Report) -> str:
    if not report.scope:
        return (
            "Scope was not supplied on the command line. **Populate this section before the report "
            "leaves the team**: list every in-scope host, network range or application, and record "
            "what was explicitly excluded."
        )
    return "\n".join("- `{}`".format(item) for item in report.scope)


def _findings(report: Report) -> str:
    if not report.findings:
        return "_No findings were raised by the automated check set._"
    blocks = []
    for index, finding in enumerate(report.findings, 1):
        blocks.append(_finding_block(index, finding))
    return "\n---\n\n".join(blocks)


def _host_inventory(report: Report) -> str:
    if not report.hosts:
        return "_No hosts were parsed from the supplied scan data._"
    rows = ["| Host | Hostname | Port | Service | Banner |", "|---|---|---|---|---|"]
    for host in report.hosts:
        if not host.open_ports:
            rows.append(
                "| {} | {} | – | – | no open ports observed |".format(
                    md_escape(host.address), md_escape(host.hostname) or "–"
                )
            )
            continue
        for port in host.open_ports:
            rows.append(
                "| {} | {} | {}/{} | {} | {} |".format(
                    md_escape(host.address),
                    md_escape(host.hostname) or "–",
                    port.number,
                    port.protocol,
                    md_escape(port.service) or "unknown",
                    md_escape(port.banner),
                )
            )
    return "\n".join(rows)


def _web_surface(report: Report) -> str:
    if not report.web_targets:
        return "_No HTTP endpoints were parsed from the supplied httpx data._"
    rows = ["| URL | Status | Title | Server | Technologies |", "|---|---|---|---|---|"]
    for target in report.web_targets:
        rows.append(
            "| {} | {} | {} | {} | {} |".format(
                md_escape(target.url),
                target.status_code if target.status_code is not None else "–",
                md_escape(target.title) or "–",
                md_escape(target.webserver) or "–",
                md_escape(", ".join(target.technologies)) or "–",
            )
        )
    return "\n".join(rows)


def _manual_review(report: Report) -> str:
    if not report.manual_review:
        return "_No version fingerprints were collected, so there is nothing queued for manual review._"
    rows = ["| Asset | Port | Fingerprint | Action |", "|---|---|---|---|"]
    for item in report.manual_review:
        parts = item.split(None, 2)
        while len(parts) < 3:
            parts.append("–")
        asset, port, rest = parts
        fingerprint, _, action = rest.partition(" — ")
        rows.append(
            "| {} | {} | {} | {} |".format(
                md_escape(asset),
                md_escape(port),
                md_escape(fingerprint),
                md_escape(action) or "–",
            )
        )
    return "\n".join(rows)


def render_markdown(report: Report, title: str | None = None) -> str:
    """Render *report* as a Markdown document."""
    template = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    return template.safe_substitute(
        title=title or "Penetration test report — {}".format(report.client),
        client=report.client,
        engagement=report.engagement or "Not specified",
        tester=report.tester or "Not specified",
        date=report.date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        exec_summary=_exec_summary(report),
        scope=_scope(report),
        findings=_findings(report),
        host_inventory=_host_inventory(report),
        web_surface=_web_surface(report),
        manual_review=_manual_review(report),
        methodology=METHODOLOGY,
        disclaimer=DISCLAIMER_FULL,
    )


def render_json(report: Report, indent: int = 2) -> str:
    """Render *report* as machine-readable JSON for downstream tooling."""
    payload = report.to_dict()
    payload["generator"] = "reconkit {}".format(__version__)
    payload["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return json.dumps(payload, indent=indent, ensure_ascii=False)
