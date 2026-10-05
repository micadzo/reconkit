"""Tests for the README hero-image generator in ``tools/``."""

import importlib.util
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

ROOT = Path(__file__).resolve().parents[1]
SVG_NS = "{http://www.w3.org/2000/svg}"

_spec = importlib.util.spec_from_file_location(
    "make_demo_svg", ROOT / "tools" / "make_demo_svg.py"
)
demo_svg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo_svg)

SAMPLE = [
    "[reconkit] examples/sample_nmap.xml: 3 host(s) parsed",
    "[reconkit] findings: 2 critical, 8 high, 4 medium, 1 low, 1 info",
]


class DemoImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svg = demo_svg.render_svg(demo_svg.build_rows(demo_svg.DEFAULT_COMMAND, SAMPLE))
        cls.root = ET.fromstring(cls.svg)

    def test_output_is_well_formed_svg(self):
        self.assertEqual(self.root.tag, SVG_NS + "svg")
        self.assertIsNotNone(self.root.get("width"))
        self.assertIsNotNone(self.root.get("height"))
        self.assertIsNotNone(self.root.get("viewBox"))

    def test_command_and_output_are_both_present(self):
        joined = "".join(e.text or "" for e in self.root.iter(SVG_NS + "text"))
        self.assertIn("reconkit report", joined)
        self.assertIn("sample_nuclei.jsonl", joined)
        self.assertIn("3 host(s) parsed", joined)

    def test_findings_line_is_colour_coded(self):
        fills = {e.text: e.get("fill") for e in self.root.iter(SVG_NS + "text")}
        self.assertEqual(fills.get("critical"), "#f85149")
        self.assertEqual(fills.get("low"), "#3fb950")
        self.assertEqual(fills.get("info"), "#8b949e")

    def test_special_characters_are_escaped(self):
        svg = demo_svg.render_svg(
            demo_svg.build_rows(["$ echo a & b <c>"], ["[reconkit] <x> & <y>"])
        )
        root = ET.fromstring(svg)  # raises if the entities were not escaped
        joined = "".join(e.text or "" for e in root.iter(SVG_NS + "text"))
        self.assertIn("a & b <c>", joined)
        self.assertIn("<x> & <y>", joined)


if __name__ == "__main__":
    unittest.main()
