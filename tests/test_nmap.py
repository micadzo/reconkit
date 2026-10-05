"""Tests for the nmap XML parser."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.parsers.nmap import parse_nmap_xml  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_nmap.xml"


class NmapParserTests(unittest.TestCase):
    def setUp(self):
        self.hosts = parse_nmap_xml(SAMPLE)

    def test_down_hosts_are_excluded_by_default(self):
        self.assertEqual(len(self.hosts), 3)
        self.assertNotIn("10.0.0.40", [h.address for h in self.hosts])

    def test_include_down_keeps_every_host(self):
        hosts = parse_nmap_xml(SAMPLE, include_down=True)
        self.assertEqual(len(hosts), 4)
        self.assertEqual(hosts[-1].state, "down")

    def test_host_attributes(self):
        host = self.hosts[0]
        self.assertEqual(host.address, "10.0.0.10")
        self.assertEqual(host.hostname, "web01.lab.internal")
        self.assertEqual(host.state, "up")
        self.assertEqual(host.label, "10.0.0.10 (web01.lab.internal)")

    def test_ports_are_sorted_and_typed(self):
        ports = self.hosts[0].ports
        self.assertEqual([p.number for p in ports], [22, 80, 3306])
        mysql = ports[2]
        self.assertEqual(mysql.service, "mysql")
        self.assertEqual(mysql.product, "MySQL")
        self.assertEqual(mysql.version, "5.7.33")
        self.assertEqual(mysql.banner, "MySQL 5.7.33")

    def test_script_output_is_captured(self):
        web = self.hosts[0].ports[1]
        self.assertIn("http-title", web.scripts)
        self.assertIn("Lab Portal", web.scripts["http-title"])

    def test_host_without_hostname(self):
        host = self.hosts[2]
        self.assertEqual(host.address, "10.0.0.30")
        self.assertEqual(host.hostname, "")
        self.assertEqual(host.label, "10.0.0.30")


if __name__ == "__main__":
    unittest.main()
