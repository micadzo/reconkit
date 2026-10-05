"""Parser for ``httpx -jsonl`` output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO, Union
from urllib.parse import urlparse

from ..models import WebTarget

Source = Union[str, Path, IO[str], IO[bytes]]


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _as_tech(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _read_text(source: Source) -> str:
    if isinstance(source, (str, Path)):
        return Path(source).read_text(encoding="utf-8", errors="replace")
    data = source.read()  # type: ignore[union-attr]
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def parse_httpx_jsonl(source: Source) -> list[WebTarget]:
    """Parse httpx JSONL output into :class:`WebTarget` objects.

    Blank lines, comment lines and malformed JSON records are skipped so that
    a partially written scan file never breaks a report run.
    """
    targets: list[WebTarget] = []

    for line in _read_text(source).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        url = str(record.get("url") or record.get("input") or "").strip()
        if not url:
            continue

        parsed = urlparse(url)
        scheme = str(record.get("scheme") or parsed.scheme)
        host = str(record.get("host") or parsed.hostname or "")
        port = _as_int(record.get("port"))
        if port is None:
            try:
                port = parsed.port
            except ValueError:
                port = None

        targets.append(
            WebTarget(
                url=url,
                status_code=_as_int(record.get("status_code", record.get("status"))),
                title=str(record.get("title") or "").strip(),
                webserver=str(record.get("webserver") or "").strip(),
                technologies=_as_tech(record.get("tech", record.get("technologies"))),
                content_length=_as_int(record.get("content_length")),
                host=host,
                port=port,
                scheme=scheme,
            )
        )

    return targets
