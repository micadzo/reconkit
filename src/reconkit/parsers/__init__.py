"""Parsers that turn third-party scanner output into reconkit models."""

from .httpx import parse_httpx_jsonl
from .nmap import parse_nmap_xml

__all__ = ["parse_nmap_xml", "parse_httpx_jsonl"]
