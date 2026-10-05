"""Command line interface for reconkit."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import __version__
from .checks import (
    DEFAULT_RULES_PATH,
    SCRIPT_RULES,
    RuleError,
    failing_findings,
    load_rules,
    manual_review_items,
    run_checks,
    sort_findings,
)
from .models import Report, SEVERITIES
from .parsers import parse_httpx_jsonl, parse_nmap_xml, parse_nuclei_jsonl
from .render import render_docx, render_html, render_json, render_markdown

PROGRAM = "reconkit"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_GATE_TRIGGERED = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Turn raw nmap, httpx and nuclei output into a clean, client-ready "
            "penetration test report."
        ),
        epilog=(
            "Example: reconkit report --nmap scan.xml --httpx probe.jsonl "
            "--client ACME --tester 'A. Tester' -o report.md"
        ),
    )
    parser.add_argument("--version", action="version", version="{} {}".format(PROGRAM, __version__))

    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="build a report from scan output")
    report.add_argument(
        "--nmap",
        action="append",
        default=[],
        metavar="FILE",
        help="nmap XML (-oX) file; repeatable",
    )
    report.add_argument(
        "--httpx",
        action="append",
        default=[],
        metavar="FILE",
        help="httpx JSONL (-jsonl) file; repeatable",
    )
    report.add_argument(
        "--nuclei",
        action="append",
        default=[],
        metavar="FILE",
        help="nuclei JSONL (-jsonl) file; repeatable",
    )
    report.add_argument("--client", default="Redacted", help="client or system owner name")
    report.add_argument("--engagement", default="", help="engagement or ticket reference")
    report.add_argument("--tester", default="", help="name of the person who performed testing")
    report.add_argument(
        "--date",
        default="",
        help="testing date (YYYY-MM-DD); defaults to today (UTC)",
    )
    report.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="TARGET",
        help="in-scope host, range or application; repeatable",
    )
    report.add_argument(
        "--in-scope-file",
        metavar="FILE",
        help="file with one in-scope target per line",
    )
    report.add_argument(
        "-o",
        "--output",
        default="-",
        metavar="FILE",
        help="output file, or '-' for stdout (default: -)",
    )
    report.add_argument(
        "--format",
        choices=("md", "json", "html", "docx"),
        default="md",
        help="output format: md, html, json or docx (default: md)",
    )
    report.add_argument(
        "--severity-min",
        choices=SEVERITIES,
        default="info",
        help="drop findings below this severity from the report",
    )
    report.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help=(
            "exit with code {} if any finding is at or above SEVERITY "
            "(useful in CI)".format(EXIT_GATE_TRIGGERED)
        ),
    )
    report.add_argument("--rules", metavar="FILE", help="custom port rules JSON file")
    report.add_argument("--quiet", action="store_true", help="suppress progress messages on stderr")

    subparsers.add_parser("list-checks", help="list every built-in check and its severity")

    return parser


def _log(quiet: bool, message: str) -> None:
    if not quiet:
        print("[{}] {}".format(PROGRAM, message), file=sys.stderr)


def _read_scope_file(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _cmd_report(args: argparse.Namespace) -> int:
    if not args.nmap and not args.httpx and not args.nuclei:
        print(
            "{}: error: at least one --nmap, --httpx or --nuclei input is required".format(
                PROGRAM
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    hosts = []
    for path in args.nmap:
        if not Path(path).is_file():
            print("{}: error: no such file: {}".format(PROGRAM, path), file=sys.stderr)
            return EXIT_ERROR
        parsed = parse_nmap_xml(path)
        _log(args.quiet, "{}: {} host(s) parsed".format(path, len(parsed)))
        hosts.extend(parsed)

    web_targets = []
    for path in args.httpx:
        if not Path(path).is_file():
            print("{}: error: no such file: {}".format(PROGRAM, path), file=sys.stderr)
            return EXIT_ERROR
        parsed = parse_httpx_jsonl(path)
        _log(args.quiet, "{}: {} endpoint(s) parsed".format(path, len(parsed)))
        web_targets.extend(parsed)

    nuclei_findings = []
    for path in args.nuclei:
        if not Path(path).is_file():
            print("{}: error: no such file: {}".format(PROGRAM, path), file=sys.stderr)
            return EXIT_ERROR
        parsed = parse_nuclei_jsonl(path)
        _log(args.quiet, "{}: {} nuclei finding(s) parsed".format(path, len(parsed)))
        nuclei_findings.extend(parsed)

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print("{}: error: {}".format(PROGRAM, exc), file=sys.stderr)
        return EXIT_ERROR
    _log(
        args.quiet,
        "loaded {} port rule(s) from {}".format(
            len(rules), args.rules or DEFAULT_RULES_PATH.name
        ),
    )

    findings = sort_findings(run_checks(hosts, web_targets, rules=rules) + nuclei_findings)
    limit_index = SEVERITIES.index(args.severity_min)
    kept = [f for f in findings if SEVERITIES.index(f.severity) <= limit_index]
    dropped = len(findings) - len(kept)

    if dropped:
        _log(args.quiet, "{} finding(s) suppressed by --severity-min".format(dropped))

    scope = list(args.scope)
    if args.in_scope_file:
        try:
            scope.extend(_read_scope_file(args.in_scope_file))
        except OSError as exc:
            print("{}: error: {}".format(PROGRAM, exc), file=sys.stderr)
            return EXIT_ERROR

    report = Report(
        client=args.client,
        engagement=args.engagement,
        tester=args.tester,
        date=args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        scope=scope,
        hosts=hosts,
        web_targets=web_targets,
        findings=kept,
        manual_review=manual_review_items(hosts, web_targets),
    )

    if args.format == "docx":
        if args.output == "-":
            print(
                "{}: error: --format docx requires -o FILE (binary output)".format(PROGRAM),
                file=sys.stderr,
            )
            return EXIT_ERROR
        try:
            rendered = render_docx(report)
        except RuntimeError as exc:
            print("{}: error: {}".format(PROGRAM, exc), file=sys.stderr)
            return EXIT_ERROR
        Path(args.output).write_bytes(rendered)
        _log(args.quiet, "wrote {} ({} bytes)".format(args.output, len(rendered)))
    else:
        if args.format == "json":
            rendered = render_json(report)
        elif args.format == "html":
            rendered = render_html(report)
        else:
            rendered = render_markdown(report)
        if args.output == "-":
            print(rendered)
        else:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
            _log(args.quiet, "wrote {} ({} bytes)".format(args.output, len(rendered)))

    counts = report.counts_by_severity()
    _log(
        args.quiet,
        "findings: {} critical, {} high, {} medium, {} low, {} info".format(
            counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]
        ),
    )

    if args.fail_on:
        gate = failing_findings(kept, args.fail_on)
        if gate:
            print(
                "{}: gate failed — {} finding(s) at or above '{}'".format(
                    PROGRAM, len(gate), args.fail_on
                ),
                file=sys.stderr,
            )
            return EXIT_GATE_TRIGGERED

    return EXIT_OK


def _cmd_list_checks(_: argparse.Namespace) -> int:
    rules = load_rules()
    print("Port rules (from {}):\n".format(DEFAULT_RULES_PATH.name))
    for rule in sorted(rules, key=lambda r: (r["severity"], r["id"])):
        print(
            "  {:<10} {:<34} ports {}".format(
                rule["severity"],
                rule["id"],
                ",".join(str(p) for p in rule["ports"]),
            )
        )
    print("\nScript rules (nmap NSE output):\n")
    for rule in sorted(SCRIPT_RULES, key=lambda r: (r["severity"], r["id"])):
        print("  {:<10} {:<34} {}".format(rule["severity"], rule["id"], rule["script"]))
    print("\nWeb rules (httpx output):\n")
    for check_id, severity in (
        ("WEB-ADMIN-INTERFACE-EXPOSED", "medium/high"),
        ("EXPOSED-NON-PRODUCTION-ENVIRONMENT", "medium"),
        ("WEB-CLEARTEXT-HTTP", "low"),
        ("WEB-SENSITIVE-PATH-EXPOSED", "high"),
    ):
        print("  {:<10} {}".format(severity, check_id))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "report":
        try:
            return _cmd_report(args)
        except KeyboardInterrupt:
            print("\n{}: interrupted".format(PROGRAM), file=sys.stderr)
            return EXIT_ERROR
    if args.command == "list-checks":
        return _cmd_list_checks(args)
    parser.print_help()
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
