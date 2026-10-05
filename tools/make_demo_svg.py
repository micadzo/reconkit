#!/usr/bin/env python3
"""Render a terminal-style SVG from captured reconkit CLI output.

The README hero image is generated from *real* command output rather than a
mock-up, so it never drifts out of sync with what the tool actually prints.

Typical use::

    reconkit report --nmap scan.xml --httpx probe.jsonl -o report.md \\
        2>&1 | grep '^\\[reconkit\\]' > demo.txt
    python tools/make_demo_svg.py demo.txt docs/demo.svg

Only the standard library is used, in keeping with the rest of the project.
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path

FONT_SIZE = 15
CHAR_WIDTH = 9.0
LINE_HEIGHT = 24
PAD_X = 24
PAD_TOP = 22
PAD_BOTTOM = 24
TITLEBAR_HEIGHT = 36
MIN_WIDTH = 720

BACKGROUND = "#0d1117"
TITLEBAR = "#161b22"
BORDER = "#30363d"
FOREGROUND = "#e6edf3"
DIM = "#8b949e"
PROMPT = "#3fb950"
ACCENT = "#58a6ff"

SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#db6d28",
    "medium": "#d29922",
    "low": "#3fb950",
    "info": "#8b949e",
}

FONT_STACK = (
    "SFMono-Regular, &quot;SF Mono&quot;, Consolas, &quot;Liberation Mono&quot;, "
    "Menlo, monospace"
)

DEFAULT_COMMAND = [
    "$ reconkit report \\",
    "    --nmap examples/sample_nmap.xml \\",
    "    --httpx examples/sample_httpx.jsonl \\",
    "    --nuclei examples/sample_nuclei.jsonl \\",
    '    --client "Example Corp" -o report.md',
]

LOG_PREFIX = "[reconkit] "


def escape(text: str) -> str:
    return html.escape(text, quote=False)


def _runs_for_command(line: str) -> list[tuple[str, str, bool]]:
    if line.startswith("$ "):
        return [(PROMPT, "$ ", True), (FOREGROUND, line[2:], False)]
    return [(FOREGROUND, line, False)]


def _runs_for_log(line: str) -> list[tuple[str, str, bool]]:
    body = line[len(LOG_PREFIX):] if line.startswith(LOG_PREFIX) else line
    runs: list[tuple[str, str, bool]] = [(DIM, LOG_PREFIX, False)]

    if body.startswith("findings:"):
        runs.append((FOREGROUND, "findings: ", True))
        for index, part in enumerate(body[len("findings: "):].split(", ")):
            if index:
                runs.append((DIM, ", ", False))
            count, _, severity = part.partition(" ")
            runs.append((FOREGROUND, count + " ", True))
            runs.append((SEVERITY_COLORS.get(severity, FOREGROUND), severity, True))
        return runs

    if "parsed" in body:
        runs.append((ACCENT, body, False))
    elif body.startswith(("loaded", "wrote")):
        runs.append((DIM, body, False))
    else:
        runs.append((FOREGROUND, body, False))
    return runs


def build_rows(command: list[str], output: list[str]) -> list[list[tuple[str, str, bool]]]:
    """Return each visual line as a list of ``(color, text, bold)`` runs."""
    rows = [_runs_for_command(line) for line in command]
    rows.append([(FOREGROUND, "", False)])
    rows.extend(_runs_for_log(line) for line in output)
    return rows


def _text_element(
    x: float, y: float, color: str, text: str, width: float, bold: bool
) -> str:
    weight = ' font-weight="600"' if bold else ""
    preserve = ' xml:space="preserve"' if text != text.strip() else ""
    return (
        '<text x="{x:.1f}" y="{y:.1f}" fill="{color}" font-size="{size}"'
        ' textLength="{width:.1f}" lengthAdjust="spacingAndGlyphs"{weight}{preserve}>'
        "{text}</text>"
    ).format(
        x=x,
        y=y,
        color=color,
        size=FONT_SIZE,
        width=width,
        weight=weight,
        preserve=preserve,
        text=escape(text),
    )


def render_svg(
    rows: list[list[tuple[str, str, bool]]],
    title: str = "reconkit — report",
) -> str:
    line_chars = [sum(len(run[1]) for run in row) for row in rows]
    max_chars = max(line_chars) if line_chars else 40
    width = max(MIN_WIDTH, int(max_chars * CHAR_WIDTH) + PAD_X * 2)
    height = TITLEBAR_HEIGHT + PAD_TOP + len(rows) * LINE_HEIGHT + PAD_BOTTOM

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}"'
        ' viewBox="0 0 {w} {h}" role="img" aria-label="{label}">'.format(
            w=width, h=height, label=escape(title)
        ),
        "<title>{}</title>".format(escape(title)),
        '<rect x="0.5" y="0.5" width="{w}" height="{h}" rx="10"'
        ' fill="{bg}" stroke="{border}"/>'.format(
            w=width - 1, h=height - 1, bg=BACKGROUND, border=BORDER
        ),
        '<path d="M0.5 10a10 10 0 0 1 10-10h{w}a10 10 0 0 1 10 10v{bar}h-{w}z"'
        ' fill="{bg}"/>'.format(w=width - 1, bar=TITLEBAR_HEIGHT - 10, bg=TITLEBAR),
        '<line x1="0.5" y1="{y}" x2="{x2}" y2="{y}" stroke="{border}"/>'.format(
            y=TITLEBAR_HEIGHT, x2=width - 0.5, border=BORDER
        ),
    ]

    for index, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        parts.append(
            '<circle cx="{cx}" cy="{cy}" r="6" fill="{color}"/>'.format(
                cx=22 + index * 20, cy=TITLEBAR_HEIGHT // 2, color=color
            )
        )

    parts.append(
        '<text x="{x}" y="{y}" fill="{fill}" font-size="12" text-anchor="middle"'
        ' font-family="{font}">{label}</text>'.format(
            x=width / 2,
            y=TITLEBAR_HEIGHT // 2 + 4,
            fill=DIM,
            font=FONT_STACK,
            label=escape(title),
        )
    )

    for row_index, row in enumerate(rows):
        baseline = TITLEBAR_HEIGHT + PAD_TOP + row_index * LINE_HEIGHT + FONT_SIZE
        cursor = float(PAD_X)
        for color, text, bold in row:
            if text:
                parts.append(
                    _text_element(cursor, baseline, color, text, len(text) * CHAR_WIDTH, bold)
                )
            cursor += len(text) * CHAR_WIDTH

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", type=Path, help="file with captured [reconkit] output lines")
    parser.add_argument("output", type=Path, help="SVG file to write")
    parser.add_argument("--title", default="reconkit — report", help="window title text")
    parser.add_argument(
        "--command",
        action="append",
        default=None,
        metavar="LINE",
        help="command transcript line; repeatable (defaults to the sample invocation)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        raw = args.input.read_text(encoding="utf-8")
    except OSError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    output_lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    if not output_lines:
        print("error: no output lines found in {}".format(args.input), file=sys.stderr)
        return 1

    command = args.command if args.command else DEFAULT_COMMAND
    svg = render_svg(build_rows(command, output_lines), title=args.title)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(svg, encoding="utf-8")
    print("wrote {} ({} lines, {} bytes)".format(args.output, len(output_lines), len(svg)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
