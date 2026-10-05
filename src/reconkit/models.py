"""Core data model for reconkit.

Everything that flows through the tool is a plain dataclass, so the parsers,
the check engine and the renderers stay completely decoupled from each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Sort order for severities (lower index == more severe).
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SEVERITIES = tuple(SEVERITY_ORDER)


def severity_rank(severity: str) -> int:
    """Return the sort rank of *severity*, tolerating unknown values."""
    return SEVERITY_ORDER.get(severity.lower(), len(SEVERITY_ORDER))


@dataclass
class Port:
    """A single port observed on a host."""

    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        """Human readable service banner, e.g. ``OpenSSH 7.4``."""
        parts = [self.product or self.service]
        if self.version:
            parts.append(self.version)
        if self.extra_info:
            parts.append("({})".format(self.extra_info))
        text = " ".join(p for p in parts if p)
        return text or "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "scripts": dict(self.scripts),
        }


@dataclass
class Host:
    """A scanned host and the ports found on it."""

    address: str
    hostname: str = ""
    state: str = "up"
    ports: list[Port] = field(default_factory=list)

    @property
    def label(self) -> str:
        """``10.0.0.10 (web01.lab.internal)`` or just the address."""
        return "{} ({})".format(self.address, self.hostname) if self.hostname else self.address

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass
class WebTarget:
    """A single URL reported by httpx."""

    url: str
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    technologies: list[str] = field(default_factory=list)
    content_length: int | None = None
    host: str = ""
    port: int | None = None
    scheme: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "webserver": self.webserver,
            "technologies": list(self.technologies),
            "content_length": self.content_length,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
        }


@dataclass
class Finding:
    """A single issue raised by a check."""

    check_id: str
    title: str
    severity: str
    asset: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "asset": self.asset,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class Report:
    """Everything needed to render an engagement report."""

    client: str = "Redacted"
    engagement: str = ""
    tester: str = ""
    date: str = ""
    scope: list[str] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    web_targets: list[WebTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    manual_review: list[str] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity.lower()] = counts.get(finding.severity.lower(), 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "client": self.client,
            "engagement": self.engagement,
            "tester": self.tester,
            "date": self.date,
            "scope": list(self.scope),
            "summary": self.counts_by_severity(),
            "hosts": [h.to_dict() for h in self.hosts],
            "web_targets": [w.to_dict() for w in self.web_targets],
            "findings": [f.to_dict() for f in self.findings],
            "manual_review": list(self.manual_review),
        }
