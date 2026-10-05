"""End-to-end tests for the command line interface."""

import io
import json
import shutil
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.cli import EXIT_ERROR, EXIT_GATE_TRIGGERED, EXIT_OK, main  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_NMAP = str(ROOT / "examples" / "sample_nmap.xml")
SAMPLE_HTTPX = str(ROOT / "examples" / "sample_httpx.jsonl")

# Scratch files are created inside the checkout rather than the system temp
# directory: the repository already owns this path, and it keeps the suite
# working in restricted environments. `tests/.tmp/` is git-ignored.
SCRATCH = ROOT / "tests" / ".tmp"


def run(argv):
    """Run the CLI and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ScratchDir:
    """Minimal stand-in for ``tempfile.TemporaryDirectory``."""

    def __init__(self, name):
        self.path = SCRATCH / name

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=True)
        return str(self.path)

    def __exit__(self, *exc_info):
        shutil.rmtree(self.path, ignore_errors=True)
        return False


class CliTests(unittest.TestCase):
    def test_report_to_stdout(self):
        code, out, _ = run(["report", "--nmap", SAMPLE_NMAP, "--httpx", SAMPLE_HTTPX])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("# Penetration test report", out)
        self.assertIn("CLEARTEXT-TELNET", out)

    def test_report_to_file(self):
        with ScratchDir("report-to-file") as tmp:
            target = Path(tmp) / "report.md"
            code, _, err = run(
                [
                    "report",
                    "--nmap",
                    SAMPLE_NMAP,
                    "--httpx",
                    SAMPLE_HTTPX,
                    "--client",
                    "Example Corp",
                    "-o",
                    str(target),
                ]
            )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(target.is_file())
            self.assertIn("Example Corp", target.read_text(encoding="utf-8"))
            self.assertIn("wrote", err)

    def test_json_format_is_machine_readable(self):
        code, out, _ = run(
            ["report", "--nmap", SAMPLE_NMAP, "--httpx", SAMPLE_HTTPX, "--format", "json"]
        )
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(len(payload["findings"]), 12)

    def test_quiet_suppresses_progress(self):
        _, _, err = run(["report", "--nmap", SAMPLE_NMAP, "--quiet"])
        self.assertEqual(err.strip(), "")

    def test_severity_min_filters_findings(self):
        _, out, _ = run(
            [
                "report",
                "--nmap",
                SAMPLE_NMAP,
                "--httpx",
                SAMPLE_HTTPX,
                "--format",
                "json",
                "--severity-min",
                "critical",
            ]
        )
        payload = json.loads(out)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["severity"], "critical")

    def test_fail_on_gate_returns_two(self):
        code, _, err = run(
            ["report", "--nmap", SAMPLE_NMAP, "--httpx", SAMPLE_HTTPX, "--fail-on", "high"]
        )
        self.assertEqual(code, EXIT_GATE_TRIGGERED)
        self.assertIn("gate failed", err)

    def test_gate_fires_on_a_critical_only_report(self):
        with ScratchDir("gate-critical-only") as tmp:
            path = Path(tmp) / "ok.md"
            code, _, err = run(
                [
                    "report",
                    "--nmap",
                    SAMPLE_NMAP,
                    "--severity-min",
                    "critical",
                    "--fail-on",
                    "info",
                    "-o",
                    str(path),
                ]
            )
        self.assertEqual(code, EXIT_GATE_TRIGGERED)
        self.assertIn("at or above 'info'", err)

    def test_gate_passes_when_nothing_matches(self):
        # A host with a single unremarkable port matches no rule at all.
        clean_scan = (
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="9999">'
            '<state state="open"/><service name="unknown"/></port></ports></host></nmaprun>'
        )
        with ScratchDir("gate-clean") as tmp:
            scan = Path(tmp) / "clean.xml"
            scan.write_text(clean_scan, encoding="utf-8")
            path = Path(tmp) / "clean.md"
            code, _, err = run(
                ["report", "--nmap", str(scan), "--fail-on", "info", "-o", str(path)]
            )
        self.assertEqual(code, EXIT_OK)
        self.assertNotIn("gate failed", err)

    def test_scope_file_is_read(self):
        with ScratchDir("scope") as tmp:
            scope = Path(tmp) / "scope.txt"
            scope.write_text("# comment\n10.0.0.0/24\napp.example.com\n", encoding="utf-8")
            _, out, _ = run(["report", "--nmap", SAMPLE_NMAP, "--in-scope-file", str(scope)])
        self.assertIn("`10.0.0.0/24`", out)
        self.assertIn("`app.example.com`", out)
        self.assertNotIn("# comment", out)

    def test_missing_input_is_an_error(self):
        code, _, err = run(["report"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("at least one", err)

    def test_missing_file_is_an_error(self):
        code, _, err = run(["report", "--nmap", "nope.xml"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no such file", err)

    def test_malformed_rules_file_is_an_error(self):
        with ScratchDir("bad-rules") as tmp:
            rules = Path(tmp) / "rules.json"
            rules.write_text("{not json", encoding="utf-8")
            code, _, err = run(["report", "--nmap", SAMPLE_NMAP, "--rules", str(rules)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not valid JSON", err)

    def test_incomplete_rules_file_is_an_error(self):
        with ScratchDir("incomplete-rules") as tmp:
            rules = Path(tmp) / "rules.json"
            rules.write_text('[{"id": "X", "title": "no severity"}]', encoding="utf-8")
            code, _, err = run(["report", "--nmap", SAMPLE_NMAP, "--rules", str(rules)])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("missing", err)

    def test_list_checks(self):
        code, out, _ = run(["list-checks"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("CLEARTEXT-TELNET", out)
        self.assertIn("SMB-MS17-010", out)
        self.assertIn("WEB-ADMIN-INTERFACE-EXPOSED", out)


if __name__ == "__main__":
    unittest.main()
