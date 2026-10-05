"""Check engine: turns parsed scan data into :class:`Finding` objects.

Three families of checks exist:

* **port rules** — data driven, loaded from ``rules/default.json`` (or a file
  supplied with ``--rules``). These are matched purely on port numbers.
* **script rules** — matched on nmap NSE script output, e.g. SMB signing or an
  anonymous FTP login.
* **web rules** — matched on httpx results, e.g. an exposed admin panel or a
  staging hostname that should not be public.

Adding a new port rule requires no code change, which is the point.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

from .models import Finding, Host, Port, WebTarget, severity_rank

DEFAULT_RULES_PATH = Path(__file__).with_name("rules") / "default.json"

#: nmap NSE scripts we know how to interpret, with a substring that must match.
SCRIPT_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "FTP-ANONYMOUS-LOGIN",
        "script": "ftp-anon",
        "contains": "Anonymous FTP login allowed",
        "title": "Anonymous FTP login permitted",
        "severity": "high",
        "description": "The FTP server accepts anonymous logins. Anyone reachable on the network can list and often download the published files.",
        "remediation": "Disable anonymous access, or restrict it to a deliberately public directory with no write permission.",
        "references": [],
    },
    {
        "id": "SMTP-OPEN-RELAY",
        "script": "smtp-open-relay",
        "contains": "open relay",
        "title": "SMTP server is an open relay",
        "severity": "high",
        "description": "The mail server forwards mail for arbitrary third parties, enabling spam and phishing that is attributed to the organisation.",
        "remediation": "Restrict relaying to authenticated users and known internal networks, and monitor for abuse.",
        "references": [],
    },
    {
        "id": "VNC-NO-AUTHENTICATION",
        "script": "vnc-info",
        "contains": "Security type: None",
        "title": "VNC server requires no authentication",
        "severity": "critical",
        "description": "The VNC server advertises security type None, meaning a remote attacker obtains an interactive desktop session without credentials.",
        "remediation": "Enable VNC authentication with a strong password, or better, bind VNC to localhost and tunnel it over SSH.",
        "references": [],
    },
    {
        "id": "SMB-SIGNING-NOT-REQUIRED",
        "script": "smb2-security-mode",
        "contains": "not required",
        "title": "SMB signing is enabled but not required",
        "severity": "medium",
        "description": "Without mandatory SMB signing the host can be coerced into authenticating to an attacker-controlled server, enabling NTLM relay.",
        "remediation": "Require SMB signing on servers and domain controllers via Group Policy, and disable NTLM where possible.",
        "references": ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"],
    },
    {
        "id": "SMB-MS17-010",
        "script": "smb-vuln-ms17-010",
        "contains": "VULNERABLE",
        "title": "Host is vulnerable to MS17-010 (EternalBlue)",
        "severity": "critical",
        "description": "The SMBv1 implementation is vulnerable to remote code execution. This vulnerability has been used by wormable ransomware campaigns.",
        "remediation": "Patch immediately, disable SMBv1 and block SMB at the network perimeter.",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"],
    },
    {
        "id": "SSL-HEARTBLEED",
        "script": "ssl-heartbleed",
        "contains": "VULNERABLE",
        "title": "TLS service is vulnerable to Heartbleed",
        "severity": "critical",
        "description": "The TLS implementation leaks process memory to unauthenticated clients, exposing private keys and session material.",
        "remediation": "Upgrade OpenSSL, then reissue certificates and invalidate all sessions.",
        "references": ["https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability"],
    },
    {
        "id": "HTTP-SHELLSHOCK",
        "script": "http-shellshock",
        "contains": "VULNERABLE",
        "title": "CGI endpoint is vulnerable to Shellshock",
        "severity": "critical",
        "description": "Bash evaluates attacker-controlled environment variables, allowing unauthenticated command execution through the CGI endpoint.",
        "remediation": "Patch Bash and remove unnecessary CGI endpoints.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    },
    {
        "id": "TLS-LEGACY-PROTOCOL",
        "script": "ssl-enum-ciphers",
        "contains": "SSLv3",
        "title": "Obsolete SSLv3 protocol offered",
        "severity": "medium",
        "description": "SSLv3 is cryptographically broken and no longer considered acceptable for any deployment.",
        "remediation": "Disable SSLv3 and TLS 1.0/1.1, leaving TLS 1.2 and TLS 1.3 only.",
        "references": [],
    },
)

#: Web application fingerprints that indicate a management interface.
ADMIN_PANEL_SIGNATURES: dict[str, tuple[str, str]] = {
    "jenkins": ("Jenkins", "high"),
    "phpmyadmin": ("phpMyAdmin", "high"),
    "adminer": ("Adminer", "high"),
    "portainer": ("Portainer", "high"),
    "rabbitmq": ("RabbitMQ management", "high"),
    "sonarqube": ("SonarQube", "medium"),
    "grafana": ("Grafana", "medium"),
    "kibana": ("Kibana", "medium"),
    "prometheus": ("Prometheus", "medium"),
    "zabbix": ("Zabbix", "medium"),
    "tomcat": ("Apache Tomcat manager", "high"),
    "gitlab": ("GitLab", "medium"),
    "nexus repository": ("Nexus Repository", "medium"),
    "kong manager": ("Kong Manager", "medium"),
    "consul": ("Consul", "high"),
    "vault": ("HashiCorp Vault", "high"),
}

#: Hostnames that usually signal a non-production environment.
#: ``internal`` is deliberately NOT in this list: the reserved ``.internal`` TLD
#: is common in lab ranges and would match every host there.
DEV_HOSTNAME_PATTERN = re.compile(
    r"(^|[.\-])(dev|develop|development|staging|stage|stg|test|testing|qa|uat|"
    r"preprod|pre-prod|pre-production|sandbox|demo|intranet|beta|old|legacy|backup)([.\-]|$)",
    re.IGNORECASE,
)

#: Paths whose exposure almost always means a deployment mistake.
SENSITIVE_PATH_PATTERN = re.compile(
    r"/(\.git|\.svn|\.hg|\.env|\.aws/credentials|\.ssh/id_rsa|"
    r"wp-config\.php\.(bak|old|save|txt)|\.DS_Store|id_rsa|"
    r"(config|backup|dump)\.(sql|zip|tar\.gz|tgz|bak|old))",
    re.IGNORECASE,
)


class RuleError(ValueError):
    """Raised when a rules file is malformed."""


def load_rules(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load port-based rules from JSON.

    Falls back to the bundled rule set when *path* is ``None``.
    """
    rules_path = Path(path) if path is not None else DEFAULT_RULES_PATH
    try:
        raw = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuleError("rules file not found: {}".format(rules_path)) from exc
    except json.JSONDecodeError as exc:
        raise RuleError("rules file is not valid JSON: {} ({})".format(rules_path, exc)) from exc

    if not isinstance(raw, list):
        raise RuleError("rules file must contain a JSON array of rule objects")

    rules: list[dict[str, Any]] = []
    for index, rule in enumerate(raw):
        if not isinstance(rule, dict):
            raise RuleError("rule #{} is not an object".format(index))
        for required in ("id", "title", "severity", "ports"):
            if required not in rule:
                raise RuleError("rule #{} is missing '{}'".format(index, required))
        ports = rule["ports"]
        if not isinstance(ports, list) or not ports:
            raise RuleError("rule {} has an empty 'ports' list".format(rule["id"]))
        rules.append(rule)
    return rules


def _asset(host: Host, port: Port) -> str:
    base = "{}:{}".format(host.address, port.number)
    return "{} ({})".format(base, host.hostname) if host.hostname else base


def _target_hostname(target: WebTarget) -> str:
    """Best available hostname for a web target.

    httpx reports the probed hostname in ``host``, but some pipelines replace it
    with the resolved IP. Preferring the hostname from the URL keeps the
    non-production check working in both cases.
    """
    try:
        from_url = urlparse(target.url).hostname
    except ValueError:
        from_url = None
    return from_url or target.host or ""


def _port_rule_findings(hosts: Sequence[Host], rules: Sequence[dict[str, Any]]) -> list[Finding]:
    by_port: dict[int, list[dict[str, Any]]] = {}
    for rule in rules:
        for port_number in rule["ports"]:
            if isinstance(port_number, int):
                by_port.setdefault(port_number, []).append(rule)

    findings: list[Finding] = []
    for host in hosts:
        for port in host.open_ports:
            for rule in by_port.get(port.number, ()):
                findings.append(
                    Finding(
                        check_id=rule["id"],
                        title=rule["title"],
                        severity=str(rule["severity"]).lower(),
                        asset=_asset(host, port),
                        description=rule.get("description", ""),
                        evidence="Open port {}/{} — service banner: {}".format(
                            port.number, port.protocol, port.banner
                        ),
                        remediation=rule.get("remediation", ""),
                        references=list(rule.get("references", [])),
                    )
                )
    return findings


def _script_rule_findings(hosts: Sequence[Host]) -> list[Finding]:
    findings: list[Finding] = []
    for host in hosts:
        for port in host.open_ports:
            for script_id, output in port.scripts.items():
                for rule in SCRIPT_RULES:
                    if rule["script"] != script_id:
                        continue
                    if rule["contains"].lower() not in output.lower():
                        continue
                    findings.append(
                        Finding(
                            check_id=rule["id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            asset=_asset(host, port),
                            description=rule["description"],
                            evidence="nmap script '{}': {}".format(
                                script_id, " ".join(output.split())[:400]
                            ),
                            remediation=rule["remediation"],
                            references=list(rule["references"]),
                        )
                    )
    return findings


def _web_rule_findings(targets: Sequence[WebTarget]) -> list[Finding]:
    findings: list[Finding] = []

    for target in targets:
        haystack = " ".join([target.title, target.webserver, *target.technologies]).lower()

        for signature, (display, severity) in ADMIN_PANEL_SIGNATURES.items():
            if signature in haystack:
                findings.append(
                    Finding(
                        check_id="WEB-ADMIN-INTERFACE-EXPOSED",
                        title="Management interface reachable: {}".format(display),
                        severity=severity,
                        asset=target.url,
                        description=(
                            "A {0} management interface is reachable over the network. "
                            "These interfaces are high-value targets: they expose configuration, "
                            "stored credentials and, in several products, remote code execution."
                        ).format(display),
                        evidence="title='{}' webserver='{}' tech={}".format(
                            target.title or "-",
                            target.webserver or "-",
                            ", ".join(target.technologies) or "-",
                        ),
                        remediation=(
                            "Place the interface behind authentication and a network access control "
                            "list or VPN, and keep the product patched to the current release."
                        ),
                        references=[],
                    )
                )
                break  # one management-interface finding per URL is enough

        hostname = _target_hostname(target)
        if hostname and DEV_HOSTNAME_PATTERN.search(hostname):
            findings.append(
                Finding(
                    check_id="EXPOSED-NON-PRODUCTION-ENVIRONMENT",
                    title="Non-production hostname is publicly reachable",
                    severity="medium",
                    asset=target.url,
                    description=(
                        "The hostname indicates a development, staging or testing environment, yet it "
                        "is reachable from the internet. Non-production systems usually run unreleased "
                        "code, carry weaker access controls and often share production data."
                    ),
                    evidence="hostname='{}' returned HTTP {}".format(
                        hostname, target.status_code if target.status_code is not None else "-"
                    ),
                    remediation=(
                        "Restrict non-production hostnames to internal networks or a VPN/zero-trust "
                        "gateway, and remove environment-specific names from production builds."
                    ),
                    references=[],
                )
            )

        if target.scheme == "http" and target.status_code in (200, 301, 302):
            findings.append(
                Finding(
                    check_id="WEB-CLEARTEXT-HTTP",
                    title="Content served over cleartext HTTP",
                    severity="low",
                    asset=target.url,
                    description=(
                        "The endpoint serves content over HTTP. Traffic, including session cookies "
                        "without the Secure attribute, can be read or modified in transit."
                    ),
                    evidence="scheme=http status={}".format(target.status_code),
                    remediation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                    references=[],
                )
            )

        if SENSITIVE_PATH_PATTERN.search(target.url):
            findings.append(
                Finding(
                    check_id="WEB-SENSITIVE-PATH-EXPOSED",
                    title="Sensitive file or directory is reachable",
                    severity="high",
                    asset=target.url,
                    description=(
                        "A path associated with version control metadata, environment files or "
                        "backups responded to a request. These files routinely disclose credentials "
                        "and full application source code."
                    ),
                    evidence="HTTP {} for {}".format(
                        target.status_code if target.status_code is not None else "-", target.url
                    ),
                    remediation=(
                        "Remove the file from the web root, deny access to dotfiles and backup "
                        "extensions at the web server, and rotate any credentials it contained."
                    ),
                    references=["https://owasp.org/www-project-top-ten/"],
                )
            )

    return findings


def manual_review_items(hosts: Sequence[Host], targets: Sequence[WebTarget]) -> list[str]:
    """Fingerprinted software that a human should compare against vendor advisories.

    reconkit deliberately does not claim CVE matches: it has no vulnerability
    database, and a wrong version-to-CVE mapping is worse than none.
    """
    items: list[str] = []
    for host in hosts:
        for port in host.open_ports:
            if port.product and port.version:
                items.append(
                    "{:<24} {:<6} {} — verify version against current vendor advisories".format(
                        host.hostname or host.address, port.number, port.banner
                    )
                )
    for target in targets:
        for tech in target.technologies:
            items.append(
                "{:<24} {:<6} {} — confirm supported release".format(
                    target.host or target.url, target.port or "-", tech
                )
            )
    # stable, de-duplicated output
    seen: set[str] = set()
    unique = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort by severity, then asset, then check id — deterministic output."""
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.asset, f.check_id),
    )


def run_checks(
    hosts: Sequence[Host],
    web_targets: Sequence[WebTarget],
    rules: Sequence[dict[str, Any]] | None = None,
) -> list[Finding]:
    """Run every check family and return the findings, ordered by severity."""
    active_rules = load_rules() if rules is None else list(rules)
    findings: list[Finding] = []
    findings.extend(_port_rule_findings(hosts, active_rules))
    findings.extend(_script_rule_findings(hosts))
    findings.extend(_web_rule_findings(web_targets))
    return sort_findings(findings)


def failing_findings(findings: Sequence[Finding], threshold: str) -> list[Finding]:
    """Findings at or above *threshold*, used by the ``--fail-on`` gate."""
    limit = severity_rank(threshold)
    return [f for f in findings if severity_rank(f.severity) <= limit]
