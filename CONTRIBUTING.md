# Contributing

Thanks for taking a look. This project is small on purpose and easy to extend.

## Adding a port rule (no Python required)

Port rules live in `src/reconkit/rules/default.json`. Add an entry:

```json
{
  "id": "EXPOSED-SOMETHING",
  "title": "Something is reachable from the network",
  "severity": "high",
  "ports": [1234],
  "description": "Why this matters, in two or three sentences.",
  "remediation": "What the system owner should actually do.",
  "references": ["https://example.com/authoritative-source"]
}
```

Guidelines:

* `id` is `SCREAMING-KEBAB-CASE` and describes the condition, not the port.
* `severity` is one of `critical`, `high`, `medium`, `low`, `info`.
* Prefer `critical` for unauthenticated remote code execution or credential exposure, `high` for
  direct paths to those, `medium` for weaknesses that need a precondition, `low` for hygiene.
* Every rule needs a `remediation` that a sysadmin can act on, not "fix the issue".
* Cite a vendor advisory, a CVE or a standards document in `references` where one exists.

## Adding a check

Script rules live in `SCRIPT_RULES` and web rules in `_web_rule_findings`, both in
`src/reconkit/checks.py`. A check must be:

* **Deterministic** — same input, same output, no network access.
* **Non-destructive** — reconkit never probes remote systems. Ever.
* **Honest** — do not claim a CVE match from a banner alone. Version fingerprints go to the
  "manual review" section instead.

## Development

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python -m unittest discover -s tests -v
```

There are no runtime dependencies, and pull requests that add one will be asked to justify it.

## Pull requests

* One logical change per pull request.
* New behaviour needs a test. Bug fixes should add the regression test first.
* Update `CHANGELOG.md` under `## [Unreleased]`.
* Run the full test suite before opening the pull request.

## Never

* Commit scan output, client material or anything from a real engagement.
* Add code that exploits a vulnerability, beyond matching it in existing output.
* Add sample data that refers to a real organisation, domain or IP address.
