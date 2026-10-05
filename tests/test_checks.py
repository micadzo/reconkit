"""Tests for the check engine."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.checks import (  # noqa: E402
    RuleError,
    failing_findings,
    load_rules,
    manual_review_items,
    run_checks,
)
from reconkit.models import Host, Port, WebTarget  # noqa: E402
from reconkit.parsers import parse_httpx_jsonl, parse_nmap_xml  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_NMAP = ROOT / "examples" / "sample_nmap.xml"
SAMPLE_HTTPX = ROOT / "examples" / "sample_httpx.jsonl"


class CheckEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosts = parse_nmap_xml(SAMPLE_NMAP)
        cls.targets = parse_httpx_jsonl(SAMPLE_HTTPX)
        cls.findings = run_checks(cls.hosts, cls.targets)

    def ids(self):
        return {f.check_id for f in self.findings}

    def test_expected_checks_fire(self):
        expected = {
            "CLEARTEXT-TELNET",
            "CLEARTEXT-FTP",
            "EXPOSED-DATABASE-MYSQL",
            "EXPOSED-SMB",
            "EXPOSED-RDP",
            "FTP-ANONYMOUS-LOGIN",
            "SMB-SIGNING-NOT-REQUIRED",
            "WEB-ADMIN-INTERFACE-EXPOSED",
            "EXPOSED-NON-PRODUCTION-ENVIRONMENT",
            "WEB-CLEARTEXT-HTTP",
            "WEB-SENSITIVE-PATH-EXPOSED",
        }
        self.assertTrue(expected.issubset(self.ids()), expected - self.ids())

    def test_finding_count_is_stable(self):
        self.assertEqual(len(self.findings), 12)

    def test_findings_are_sorted_by_severity(self):
        ranks = [f.severity for f in self.findings]
        order = ["critical", "high", "medium", "low", "info"]
        self.assertEqual(ranks, sorted(ranks, key=order.index))
        self.assertEqual(self.findings[0].severity, "critical")

    def test_telnet_is_critical_and_names_the_asset(self):
        finding = next(f for f in self.findings if f.check_id == "CLEARTEXT-TELNET")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.asset, "10.0.0.30:23")
        self.assertIn("23/tcp", finding.evidence)

    def test_asset_includes_hostname_when_known(self):
        finding = next(f for f in self.findings if f.check_id == "EXPOSED-DATABASE-MYSQL")
        self.assertEqual(finding.asset, "10.0.0.10:3306 (web01.lab.internal)")

    def test_only_one_admin_finding_per_url(self):
        admin = [f for f in self.findings if f.check_id == "WEB-ADMIN-INTERFACE-EXPOSED"]
        self.assertEqual(len(admin), len({f.asset for f in admin}))

    def test_every_finding_has_remediation(self):
        for finding in self.findings:
            self.assertTrue(finding.remediation, finding.check_id)
            self.assertTrue(finding.description, finding.check_id)

    def test_counts_match_findings(self):
        from reconkit.models import Report

        report = Report(findings=self.findings)
        counts = report.counts_by_severity()
        self.assertEqual(sum(counts.values()), len(self.findings))


class CustomRuleTests(unittest.TestCase):
    def test_closed_port_does_not_fire(self):
        host = Host(address="10.1.1.1", ports=[Port(number=23, state="closed")])
        self.assertEqual(run_checks([host], []), [])

    def test_unknown_port_produces_nothing(self):
        host = Host(address="10.1.1.1", ports=[Port(number=9999, state="open")])
        self.assertEqual(run_checks([host], []), [])

    def test_custom_rules_can_be_supplied(self):
        rules = [
            {
                "id": "CUSTOM-1234",
                "title": "Something interesting",
                "severity": "low",
                "ports": [1234],
                "description": "d",
                "remediation": "r",
            }
        ]
        host = Host(address="10.1.1.1", ports=[Port(number=1234, state="open")])
        findings = run_checks([host], [], rules=rules)
        self.assertEqual([f.check_id for f in findings], ["CUSTOM-1234"])

    def test_missing_rules_file_raises(self):
        with self.assertRaises(RuleError):
            load_rules("does-not-exist.json")

    def test_default_rules_load(self):
        rules = load_rules()
        self.assertGreater(len(rules), 10)
        self.assertTrue(all("ports" in rule for rule in rules))


class ManualReviewTests(unittest.TestCase):
    def test_fingerprints_are_collected(self):
        items = manual_review_items(parse_nmap_xml(SAMPLE_NMAP), parse_httpx_jsonl(SAMPLE_HTTPX))
        self.assertTrue(any("OpenSSH 7.4" in item for item in items))
        self.assertTrue(any("MySQL 5.7.33" in item for item in items))
        self.assertEqual(len(items), len(set(items)), "items must be de-duplicated")

    def test_no_fingerprint_no_item(self):
        host = Host(address="10.1.1.1", ports=[Port(number=22, state="open", service="ssh")])
        self.assertEqual(manual_review_items([host], []), [])


class FailOnTests(unittest.TestCase):
    def setUp(self):
        self.findings = run_checks(parse_nmap_xml(SAMPLE_NMAP), parse_httpx_jsonl(SAMPLE_HTTPX))

    def test_gate_triggers_on_critical(self):
        self.assertEqual(len(failing_findings(self.findings, "critical")), 1)

    def test_gate_triggers_on_high(self):
        self.assertEqual(len(failing_findings(self.findings, "high")), 8)

    def test_gate_is_empty_when_nothing_is_severe_enough(self):
        low_only = [f for f in self.findings if f.severity == "low"]
        self.assertEqual(failing_findings(low_only, "high"), [])


class WebRuleEdgeCaseTests(unittest.TestCase):
    def test_http_redirect_is_reported_as_cleartext(self):
        target = WebTarget(
            url="http://app.example.com/", scheme="http", status_code=301, host="app.example.com"
        )
        ids = {f.check_id for f in run_checks([], [target])}
        self.assertIn("WEB-CLEARTEXT-HTTP", ids)

    def test_https_error_page_is_not_reported(self):
        target = WebTarget(
            url="https://app.example.com/", scheme="https", status_code=403, host="app.example.com"
        )
        self.assertEqual(run_checks([], [target]), [])

    def test_hostname_falls_back_to_the_url(self):
        # Some pipelines record the resolved IP in `host`; the URL still wins.
        target = WebTarget(url="https://staging.example.com/", host="203.0.113.7", scheme="https")
        ids = {f.check_id for f in run_checks([], [target])}
        self.assertIn("EXPOSED-NON-PRODUCTION-ENVIRONMENT", ids)


if __name__ == "__main__":
    unittest.main()
