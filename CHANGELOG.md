# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-05

### Added

- `reconkit report` — build a report from nmap XML, httpx JSONL and nuclei JSONL input.
- 25 data-driven port rules in `src/reconkit/rules/default.json`, overridable with `--rules`.
- 8 nmap NSE script checks, including anonymous FTP, SMB signing, MS17-010 and Heartbleed.
- Web surface checks: exposed management interfaces, non-production hostnames, cleartext HTTP and
  sensitive paths.
- Manual-review queue for software version fingerprints (deliberately no CVE matching).
- nuclei `-jsonl` parser (`--nuclei FILE`); findings merge with nmap and httpx results.
- Four output formats: Markdown, self-contained HTML, DOCX (opt-in via `pip install 'reconkit[docx]'`)
  and machine-readable JSON.
- `reconkit list-checks` to print every built-in check.
- `--fail-on SEVERITY` gate for CI pipelines and a `--severity-min` filter.
- Unit test suite covering parsers, checks, renderers and the CLI end to end.

[Unreleased]: https://github.com/micadzo/reconkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/micadzo/reconkit/releases/tag/v0.1.0
