# reconkit

**Turn raw `nmap` and `httpx` output into a clean, client-ready penetration test report.**

[![CI](https://github.com/micadzo/reconkit/actions/workflows/ci.yml/badge.svg)](https://github.com/micadzo/reconkit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)](#design-decisions)

Every penetration test ends the same way: hours lost turning scan output into a document a client
will actually read. `reconkit` does the mechanical part â€” parse, correlate, order by severity,
render â€” so the tester can spend that time on the part that needs a human: validating findings and
writing the narrative.

```console
$ reconkit report --nmap scan.xml --httpx probe.jsonl \
    --client "Example Corp" --tester "A. Tester" \
    --scope 10.0.0.0/24 -o report.md

[reconkit] scan.xml: 3 host(s) parsed
[reconkit] probe.jsonl: 6 endpoint(s) parsed
[reconkit] loaded 25 port rule(s) from default.json
[reconkit] wrote report.md (12982 bytes)
[reconkit] findings: 1 critical, 7 high, 3 medium, 1 low, 0 info
```

See the output: [`examples/demo_report.md`](examples/demo_report.md).

---

## Why this exists

Writing the report is the part of pentesting that juniors are worst at and that clients judge most
harshly. Most tooling automates *finding* things; almost none automates the boring 80% of
*documenting* them. `reconkit` takes the opposite position: it is deliberately a reporting tool.

It also refuses to overclaim. It does **not** match banners to CVEs. A wrong version-to-CVE mapping
is worse than no mapping, because it burns the tester's credibility in front of the client. Instead,
every detected version is queued in a **manual review** section with the explicit instruction to
check it against vendor advisories.

## Features

- **Parses what you already have** â€” `nmap -oX` XML and `httpx -jsonl`, the two files almost every
  external recon workflow produces.
- **25 data-driven port rules** covering cleartext legacy services, exposed databases, remote
  management interfaces and container APIs.
- **8 NSE script checks** â€” anonymous FTP, open SMTP relay, unauthenticated VNC, SMB signing, and
  MS17-010 / Heartbleed / Shellshock / SSLv3 from script output.
- **Web surface checks** â€” exposed management interfaces (Jenkins, Grafana, phpMyAdmin, â€¦),
  publicly reachable non-production hostnames, cleartext HTTP and sensitive paths such as `/.git/`.
- **Extensible without code** â€” add a port rule by editing JSON. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **`--fail-on SEVERITY`** â€” exit code `2` when a finding meets a threshold, so reconkit drops
  straight into a CI pipeline.
- **Markdown and JSON output** â€” human-readable report, machine-readable findings.
- **Deterministic** â€” no network access, no timestamps in the findings, stable sort order.

## Install

`reconkit` has **zero runtime dependencies** and requires Python 3.9 or newer.

```bash
git clone https://github.com/micadzo/reconkit.git
cd reconkit
pip install -e .
```

Or run it straight from the source tree without installing anything:

```bash
PYTHONPATH=src python -m reconkit report --nmap scan.xml
```

## Usage

### Build a report

```bash
# Markdown to stdout
reconkit report --nmap scan.xml --httpx probe.jsonl

# Full engagement metadata, written to a file
reconkit report \
  --nmap internal.xml --nmap dmz.xml \
  --httpx internal.jsonl \
  --client "Example Corp" \
  --engagement "ENG-2024-001" \
  --tester "A. Tester" \
  --date 2024-05-01 \
  --scope 10.0.0.0/24 --scope app.example.com \
  -o report.md
```

### Collect the input files

```bash
nmap -sV -sC -oX scan.xml 10.0.0.0/24
httpx -l hosts.txt -jsonl -o probe.jsonl -title -tech-detect -status-code
```

### Other commands

```bash
reconkit list-checks                  # print every built-in check
reconkit report --nmap scan.xml --format json | jq '.summary'
reconkit report --nmap scan.xml --severity-min high -o critical-only.md
```

### In CI

```bash
reconkit report --nmap scan.xml --fail-on high -o report.md
# exit code 2 => at least one high or critical finding
```

| Exit code | Meaning |
|---|---|
| `0` | Report produced, no finding met the `--fail-on` threshold |
| `1` | Usage error, missing file or malformed rules |
| `2` | `--fail-on` gate triggered |

## What it checks

| Family | Count | Source |
|---|---|---|
| Port exposure rules | 25 | `src/reconkit/rules/default.json` |
| nmap NSE script rules | 8 | `checks.py â†’ SCRIPT_RULES` |
| Web surface rules | 4 | `checks.py â†’ _web_rule_findings` |
| Version fingerprints (manual review) | â€” | collected from nmap and httpx |

Run `reconkit list-checks` for the full list with severities.

Custom rule set:

```bash
reconkit report --nmap scan.xml --rules my-rules.json
```

```json
[
  {
    "id": "EXPOSED-GRAFANA",
    "title": "Grafana dashboard reachable",
    "severity": "medium",
    "ports": [3000],
    "description": "Grafana exposes dashboards, datasource credentials and often unauthenticated admin endpoints.",
    "remediation": "Require authentication, restrict source networks and keep Grafana patched.",
    "references": ["https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/"]
  }
]
```

## Design decisions

**Zero runtime dependencies.** A security tool that a reviewer can audit in one sitting is worth
more than a convenient one. Everything is standard library: `argparse`, `xml.etree`, `json`,
`dataclasses`, `string.Template`. The test suite runs on `unittest` for the same reason.

**Rules as data, logic as code.** Anything that is a fact about a port belongs in JSON and can be
changed without touching Python. Anything that requires interpreting output â€” NSE scripts, web
fingerprints â€” stays in code, where it can be tested.

**No CVE matching.** See above. Overclaiming is the fastest way to lose a client's trust.

**Deterministic output.** Same inputs produce byte-identical reports apart from the generation
timestamp, which makes reports diffable between engagement runs.

## Project layout

```
reconkit/
â”œâ”€â”€ src/reconkit/
â”‚   â”œâ”€â”€ cli.py              # argument parsing, exit codes
â”‚   â”œâ”€â”€ models.py           # Host, Port, WebTarget, Finding, Report
â”‚   â”œâ”€â”€ checks.py           # check engine
â”‚   â”œâ”€â”€ render.py           # Markdown and JSON renderers
â”‚   â”œâ”€â”€ parsers/
â”‚   â”‚   â”œâ”€â”€ nmap.py         # nmap -oX XML
â”‚   â”‚   â””â”€â”€ httpx.py        # httpx -jsonl
â”‚   â”œâ”€â”€ rules/default.json  # 25 port rules
â”‚   â””â”€â”€ templates/report.md.tmpl
â”œâ”€â”€ examples/               # synthetic sample input + demo output
â”œâ”€â”€ tests/                  # 55 unit and end-to-end tests
â””â”€â”€ .github/workflows/ci.yml
```

## Development

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

55 tests cover the parsers, the check engine, both renderers and the CLI end to end.

## Disclaimer

`reconkit` reads files that other tools produced; it never contacts a remote system. It is still a
tool that describes how to attack infrastructure. **Use it only on systems you own or have written
authorisation to test**, and never publish output, hostnames or findings from an engagement without
the owner's consent. Read [`DISCLAIMER.md`](DISCLAIMER.md) before your first run.

## License

MIT â€” see [`LICENSE`](LICENSE).
