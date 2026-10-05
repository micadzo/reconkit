# Penetration test report — Example Corp

| | |
|---|---|
| **Client / owner** | Example Corp |
| **Engagement** | Not specified |
| **Tested by** | Not specified |
| **Testing date** | 2026-10-05 |
| **Report generated** | 2026-10-05 02:43 UTC |
| **Generator** | reconkit 0.1.0 |

## 1. Executive summary

12 finding(s) were raised across 3 host(s) and 6 HTTP endpoint(s). The highest severity observed is **CRITICAL**. Address critical and high findings first: they represent reachable paths to credential theft or remote code execution.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 7 |
| Medium | 3 |
| Low | 1 |
| Info | 0 |
| **Total** | **12** |

**Observed attack surface**

- Hosts reported up: **3**
- Open ports: **8**
- HTTP endpoints probed: **6**

**Priority items**

1. `10.0.0.30:23` — Telnet service exposed (critical)
2. `10.0.0.10:3306 (web01.lab.internal)` — MySQL/MariaDB reachable from the network (high)
3. `10.0.0.20:21 (files01.lab.internal)` — FTP service exposed (high)
4. `10.0.0.20:21 (files01.lab.internal)` — Anonymous FTP login permitted (high)
5. `10.0.0.20:3389 (files01.lab.internal)` — Remote Desktop Protocol exposed (high)

## 2. Scope

- `10.0.0.0/24`

## 3. Findings

### 1. CRITICAL — Telnet service exposed

| | |
|---|---|
| **Check ID** | `CLEARTEXT-TELNET` |
| **Severity** | Critical |
| **Affected asset** | `10.0.0.30:23` |

**Description**

Telnet transmits the entire session, including credentials, without encryption. Any host on the path can capture or modify it.

**Evidence**

```
Open port 23/tcp — service banner: telnet
```

**Remediation**

Disable the Telnet service and replace it with SSH. If legacy equipment requires Telnet, restrict it to a dedicated management VLAN behind a jump host.

**References**

- https://www.cisa.gov/news-events/alerts/2014/04/08/telnet-deprecated

---

### 2. HIGH — MySQL/MariaDB reachable from the network

| | |
|---|---|
| **Check ID** | `EXPOSED-DATABASE-MYSQL` |
| **Severity** | High |
| **Affected asset** | `10.0.0.10:3306 (web01.lab.internal)` |

**Description**

A database port is reachable over the network. Database services should not normally be exposed beyond the application tier.

**Evidence**

```
Open port 3306/tcp — service banner: MySQL 5.7.33
```

**Remediation**

Bind the database to localhost or the application subnet and enforce firewall rules. Require strong per-application credentials and audit accounts for weak or shared passwords.

**References**

- https://owasp.org/www-project-top-ten/

---

### 3. HIGH — FTP service exposed

| | |
|---|---|
| **Check ID** | `CLEARTEXT-FTP` |
| **Severity** | High |
| **Affected asset** | `10.0.0.20:21 (files01.lab.internal)` |

**Description**

FTP sends credentials and file contents in cleartext and is frequently misconfigured to allow anonymous access.

**Evidence**

```
Open port 21/tcp — service banner: vsftpd 3.0.3
```

**Remediation**

Replace FTP with SFTP or FTPS. If FTP must remain, enforce TLS and restrict source addresses.

---

### 4. HIGH — Anonymous FTP login permitted

| | |
|---|---|
| **Check ID** | `FTP-ANONYMOUS-LOGIN` |
| **Severity** | High |
| **Affected asset** | `10.0.0.20:21 (files01.lab.internal)` |

**Description**

The FTP server accepts anonymous logins. Anyone reachable on the network can list and often download the published files.

**Evidence**

```
nmap script 'ftp-anon': Anonymous FTP login allowed (FTP code 230)
```

**Remediation**

Disable anonymous access, or restrict it to a deliberately public directory with no write permission.

---

### 5. HIGH — Remote Desktop Protocol exposed

| | |
|---|---|
| **Check ID** | `EXPOSED-RDP` |
| **Severity** | High |
| **Affected asset** | `10.0.0.20:3389 (files01.lab.internal)` |

**Description**

RDP reachable from an untrusted network is a primary initial-access vector for ransomware operators, through both credential attacks and pre-auth vulnerabilities.

**Evidence**

```
Open port 3389/tcp — service banner: Microsoft Terminal Services
```

**Remediation**

Place RDP behind a VPN or a zero-trust gateway, enable Network Level Authentication, enforce account lockout and MFA, and restrict source addresses.

**References**

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a

---

### 6. HIGH — SMB file sharing exposed

| | |
|---|---|
| **Check ID** | `EXPOSED-SMB` |
| **Severity** | High |
| **Affected asset** | `10.0.0.20:445 (files01.lab.internal)` |

**Description**

SMB is reachable from an untrusted network. Historically this has exposed the service to wormable remote code execution and to relay attacks when signing is not enforced.

**Evidence**

```
Open port 445/tcp — service banner: microsoft-ds
```

**Remediation**

Block SMB at the network perimeter, require SMB signing, disable SMBv1 and remove anonymous share access.

**References**

- https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security

---

### 7. HIGH — Management interface reachable: Jenkins

| | |
|---|---|
| **Check ID** | `WEB-ADMIN-INTERFACE-EXPOSED` |
| **Severity** | High |
| **Affected asset** | `https://jenkins.lab.internal:8080/` |

**Description**

A Jenkins management interface is reachable over the network. These interfaces are high-value targets: they expose configuration, stored credentials and, in several products, remote code execution.

**Evidence**

```
title='Dashboard [Jenkins]' webserver='Jetty 9.4.31' tech=Jenkins, Java
```

**Remediation**

Place the interface behind authentication and a network access control list or VPN, and keep the product patched to the current release.

---

### 8. HIGH — Sensitive file or directory is reachable

| | |
|---|---|
| **Check ID** | `WEB-SENSITIVE-PATH-EXPOSED` |
| **Severity** | High |
| **Affected asset** | `https://web01.lab.internal/.git/config` |

**Description**

A path associated with version control metadata, environment files or backups responded to a request. These files routinely disclose credentials and full application source code.

**Evidence**

```
HTTP 200 for https://web01.lab.internal/.git/config
```

**Remediation**

Remove the file from the web root, deny access to dotfiles and backup extensions at the web server, and rotate any credentials it contained.

**References**

- https://owasp.org/www-project-top-ten/

---

### 9. MEDIUM — SMB signing is enabled but not required

| | |
|---|---|
| **Check ID** | `SMB-SIGNING-NOT-REQUIRED` |
| **Severity** | Medium |
| **Affected asset** | `10.0.0.20:445 (files01.lab.internal)` |

**Description**

Without mandatory SMB signing the host can be coerced into authenticating to an attacker-controlled server, enabling NTLM relay.

**Evidence**

```
nmap script 'smb2-security-mode': | Message signing enabled but not required
```

**Remediation**

Require SMB signing on servers and domain controllers via Group Policy, and disable NTLM where possible.

**References**

- https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security

---

### 10. MEDIUM — Management interface reachable: Grafana

| | |
|---|---|
| **Check ID** | `WEB-ADMIN-INTERFACE-EXPOSED` |
| **Severity** | Medium |
| **Affected asset** | `https://grafana.lab.internal/` |

**Description**

A Grafana management interface is reachable over the network. These interfaces are high-value targets: they expose configuration, stored credentials and, in several products, remote code execution.

**Evidence**

```
title='Grafana' webserver='nginx' tech=Grafana
```

**Remediation**

Place the interface behind authentication and a network access control list or VPN, and keep the product patched to the current release.

---

### 11. MEDIUM — Non-production hostname is publicly reachable

| | |
|---|---|
| **Check ID** | `EXPOSED-NON-PRODUCTION-ENVIRONMENT` |
| **Severity** | Medium |
| **Affected asset** | `https://staging.lab.internal/` |

**Description**

The hostname indicates a development, staging or testing environment, yet it is reachable from the internet. Non-production systems usually run unreleased code, carry weaker access controls and often share production data.

**Evidence**

```
hostname='staging.lab.internal' returned HTTP 200
```

**Remediation**

Restrict non-production hostnames to internal networks or a VPN/zero-trust gateway, and remove environment-specific names from production builds.

---

### 12. LOW — Content served over cleartext HTTP

| | |
|---|---|
| **Check ID** | `WEB-CLEARTEXT-HTTP` |
| **Severity** | Low |
| **Affected asset** | `http://web01.lab.internal/` |

**Description**

The endpoint serves content over HTTP. Traffic, including session cookies without the Secure attribute, can be read or modified in transit.

**Evidence**

```
scheme=http status=200
```

**Remediation**

Redirect all HTTP traffic to HTTPS and enable HSTS.


## 4. Asset inventory

| Host | Hostname | Port | Service | Banner |
|---|---|---|---|---|
| 10.0.0.10 | web01.lab.internal | 22/tcp | ssh | OpenSSH 7.4 (protocol 2.0) |
| 10.0.0.10 | web01.lab.internal | 80/tcp | http | nginx 1.18.0 |
| 10.0.0.10 | web01.lab.internal | 3306/tcp | mysql | MySQL 5.7.33 |
| 10.0.0.20 | files01.lab.internal | 21/tcp | ftp | vsftpd 3.0.3 |
| 10.0.0.20 | files01.lab.internal | 445/tcp | microsoft-ds | microsoft-ds |
| 10.0.0.20 | files01.lab.internal | 3389/tcp | ms-wbt-server | Microsoft Terminal Services |
| 10.0.0.30 | – | 23/tcp | telnet | telnet |
| 10.0.0.30 | – | 8080/tcp | http | Jetty 9.4.31.v20200723 |

## 5. Web surface

| URL | Status | Title | Server | Technologies |
|---|---|---|---|---|
| http://web01.lab.internal/ | 200 | Lab Portal — internal documentation | nginx/1.18.0 | Nginx, PHP, Ubuntu |
| https://jenkins.lab.internal:8080/ | 200 | Dashboard [Jenkins] | Jetty 9.4.31 | Jenkins, Java |
| https://staging.lab.internal/ | 200 | Staging - Lab Portal | nginx | Nginx |
| https://files01.lab.internal/ | 404 | – | nginx | – |
| https://web01.lab.internal/.git/config | 200 | – | nginx | – |
| https://grafana.lab.internal/ | 302 | Grafana | nginx | Grafana |

## 6. Manual review required

| Asset | Port | Fingerprint | Action |
|---|---|---|---|
| web01.lab.internal | 22 | OpenSSH 7.4 (protocol 2.0) | verify version against current vendor advisories |
| web01.lab.internal | 80 | nginx 1.18.0 | verify version against current vendor advisories |
| web01.lab.internal | 3306 | MySQL 5.7.33 | verify version against current vendor advisories |
| files01.lab.internal | 21 | vsftpd 3.0.3 | verify version against current vendor advisories |
| 10.0.0.30 | 8080 | Jetty 9.4.31.v20200723 | verify version against current vendor advisories |
| web01.lab.internal | 80 | Nginx | confirm supported release |
| web01.lab.internal | 80 | PHP | confirm supported release |
| web01.lab.internal | 80 | Ubuntu | confirm supported release |
| jenkins.lab.internal | 8080 | Jenkins | confirm supported release |
| jenkins.lab.internal | 8080 | Java | confirm supported release |
| staging.lab.internal | 443 | Nginx | confirm supported release |
| grafana.lab.internal | 443 | Grafana | confirm supported release |

## 7. Methodology and limitations

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


## 8. Disclaimer

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


