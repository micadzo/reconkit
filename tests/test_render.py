"""Tests for the Markdown and JSON renderers."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.checks import manual_review_items, run_checks  # noqa: E402
from reconkit.models import Finding, Report  # noqa: E402
from reconkit.parsers import parse_httpx_jsonl, parse_nmap_xml  # noqa: E402
from reconkit.render import (
    html_escape,
    md_escape,
    render_docx,
    render_html,
    render_json,
    render_markdown,
)  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def build_report() -> Report:
    hosts = parse_nmap_xml(ROOT / "examples" / "sample_nmap.xml")
    targets = parse_httpx_jsonl(ROOT / "examples" / "sample_httpx.jsonl")
    return Report(
        client="Example Corp",
        engagement="ENG-2024-001",
        tester="A. Tester",
        date="2024-05-01",
        scope=["10.0.0.0/24"],
        hosts=hosts,
        web_targets=targets,
        findings=run_checks(hosts, targets),
        manual_review=manual_review_items(hosts, targets),
    )


class MarkdownRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build_report()
        cls.markdown = render_markdown(cls.report)

    def test_all_sections_present(self):
        for heading in (
            "## 1. Executive summary",
            "## 2. Scope",
            "## 3. Findings",
            "## 4. Asset inventory",
            "## 5. Web surface",
            "## 6. Manual review required",
            "## 7. Methodology and limitations",
            "## 8. Disclaimer",
        ):
            self.assertIn(heading, self.markdown)

    def test_metadata_is_rendered(self):
        self.assertIn("Example Corp", self.markdown)
        self.assertIn("ENG-2024-001", self.markdown)
        self.assertIn("A. Tester", self.markdown)
        self.assertIn("2024-05-01", self.markdown)

    def test_assets_appear_in_the_inventory(self):
        self.assertIn("web01.lab.internal", self.markdown)
        self.assertIn("MySQL 5.7.33", self.markdown)

    def test_no_unsubstituted_placeholders(self):
        self.assertNotIn("$findings", self.markdown)
        self.assertNotIn("$client", self.markdown)

    def test_empty_report_renders_without_findings(self):
        text = render_markdown(Report(client="Nobody"))
        self.assertIn("No findings were raised", text)
        self.assertIn("Scope was not supplied", text)

    def test_pipes_are_escaped_in_tables(self):
        finding = Finding(
            check_id="X",
            title="A | B",
            severity="low",
            asset="10.0.0.1:80 | primary",
            description="d",
        )
        report = Report(findings=[finding])
        text = render_markdown(report)
        self.assertIn(r"10.0.0.1:80 \| primary", text)

    def test_md_escape_helper(self):
        self.assertEqual(md_escape("a|b\nc"), r"a\|b c")


class JsonRendererTests(unittest.TestCase):
    def test_json_round_trips(self):
        payload = json.loads(render_json(build_report()))
        self.assertEqual(payload["client"], "Example Corp")
        self.assertEqual(len(payload["findings"]), 12)
        self.assertEqual(payload["summary"]["critical"], 1)
        self.assertEqual(len(payload["hosts"]), 3)
        self.assertIn("generator", payload)


try:
    import docx  # noqa: F401

    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False


class HtmlRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = render_html(build_report())

    def test_html_document_structure(self):
        self.assertIn("<!DOCTYPE html>", self.html)
        self.assertIn("<title>", self.html)
        self.assertIn("1. Executive summary", self.html)
        self.assertIn("3. Findings", self.html)
        self.assertIn("8. Disclaimer", self.html)

    def test_severity_badge_rendered(self):
        self.assertIn('class="sev sev-critical"', self.html)

    def test_asset_appears(self):
        self.assertIn("web01.lab.internal", self.html)

    def test_html_escape(self):
        self.assertEqual(html_escape('<a href="x">'), "&lt;a href=&quot;x&quot;&gt;")

    def test_empty_report(self):
        html = render_html(Report(client="Nobody"))
        self.assertIn("No findings were raised", html)


@unittest.skipUnless(HAS_DOCX, "python-docx not installed")
class DocxRendererTests(unittest.TestCase):
    def test_docx_is_a_valid_zip(self):
        import io as _io
        import zipfile

        data = render_docx(build_report())
        self.assertEqual(data[:2], b"PK")
        with zipfile.ZipFile(_io.BytesIO(data)) as archive:
            self.assertIn("word/document.xml", archive.namelist())

    def test_docx_contains_report_text(self):
        import io as _io
        import zipfile

        data = render_docx(build_report())
        with zipfile.ZipFile(_io.BytesIO(data)) as archive:
            xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("reconkit", xml)
        self.assertIn("Example Corp", xml)


if __name__ == "__main__":
    unittest.main()
