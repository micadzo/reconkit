"""Tests for the nuclei JSONL parser."""

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.parsers.nuclei import parse_nuclei_jsonl  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_nuclei.jsonl"


class NucleiParserTests(unittest.TestCase):
    def test_sample_is_parsed(self):
        findings = parse_nuclei_jsonl(SAMPLE)
        self.assertEqual(len(findings), 4)

    def test_severity_is_normalised(self):
        findings = {f.check_id: f for f in parse_nuclei_jsonl(SAMPLE)}
        self.assertEqual(findings["cves/2021/CVE-2021-44228"].severity, "critical")
        self.assertEqual(findings["exposed-panel-grafana"].severity, "high")
        self.assertEqual(findings["weak-tls-v1-0"].severity, "medium")
        self.assertEqual(findings["http-missing-security-headers"].severity, "info")

    def test_fields_are_mapped(self):
        log4shell = next(
            f for f in parse_nuclei_jsonl(SAMPLE) if "CVE-2021-44228" in f.check_id
        )
        self.assertEqual(log4shell.title, "Apache Log4j RCE (Log4Shell)")
        self.assertIn("CVE-2021-44228", log4shell.references)
        self.assertIn("CWE-502", log4shell.references)
        self.assertTrue(log4shell.remediation)
        self.assertTrue(log4shell.description)

    def test_unknown_severity_falls_back_to_info(self):
        record = '{"template-id":"x","info":{"name":"n","severity":"unknown"}}'
        findings = parse_nuclei_jsonl(io.StringIO(record))
        self.assertEqual(findings[0].severity, "info")

    def test_malformed_and_blank_lines_are_skipped(self):
        payload = '\n# comment\n{"template-id":"a","info":{"name":"A","severity":"high"}}\n{bad}\n'
        findings = parse_nuclei_jsonl(io.StringIO(payload))
        self.assertEqual([f.check_id for f in findings], ["a"])

    def test_references_accept_scalar(self):
        record = '{"template-id":"s","info":{"reference":"https://x.test","severity":"low"}}'
        findings = parse_nuclei_jsonl(io.StringIO(record))
        self.assertEqual(findings[0].references, ["https://x.test"])

    def test_missing_severity_defaults_to_info(self):
        record = '{"template-id":"t","info":{"name":"T"}}'
        findings = parse_nuclei_jsonl(io.StringIO(record))
        self.assertEqual(findings[0].severity, "info")
        self.assertTrue(findings[0].description)
        self.assertTrue(findings[0].remediation)


if __name__ == "__main__":
    unittest.main()
