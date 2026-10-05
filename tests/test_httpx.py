"""Tests for the httpx JSONL parser."""

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.parsers.httpx import parse_httpx_jsonl  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_httpx.jsonl"


class HttpxParserTests(unittest.TestCase):
    def test_sample_is_parsed(self):
        targets = parse_httpx_jsonl(SAMPLE)
        self.assertEqual(len(targets), 6)
        first = targets[0]
        self.assertEqual(first.url, "http://web01.lab.internal/")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.scheme, "http")
        self.assertEqual(first.host, "web01.lab.internal")
        self.assertEqual(first.port, 80)
        self.assertIn("Nginx", first.technologies)

    def test_blank_and_comment_lines_are_skipped(self):
        payload = '\n# comment\n{"url":"https://example.com/"}\n\n'
        targets = parse_httpx_jsonl(io.StringIO(payload))
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "https://example.com/")

    def test_malformed_records_do_not_raise(self):
        payload = '{"url":"https://a.test/"}\n{not json}\nnot json at all\n{"url":""}\n'
        targets = parse_httpx_jsonl(io.StringIO(payload))
        self.assertEqual([t.url for t in targets], ["https://a.test/"])

    def test_fields_fall_back_to_url_parsing(self):
        targets = parse_httpx_jsonl(io.StringIO('{"url":"https://host.example.com:8443/admin"}'))
        target = targets[0]
        self.assertEqual(target.host, "host.example.com")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.scheme, "https")
        self.assertIsNone(target.status_code)

    def test_technology_string_is_split(self):
        targets = parse_httpx_jsonl(io.StringIO('{"url":"https://a.test/","tech":"Nginx, PHP"}'))
        self.assertEqual(targets[0].technologies, ["Nginx", "PHP"])

    def test_status_alias_is_accepted(self):
        targets = parse_httpx_jsonl(io.StringIO('{"url":"https://a.test/","status":403}'))
        self.assertEqual(targets[0].status_code, 403)


if __name__ == "__main__":
    unittest.main()
