"""Parser for ``nmap -oX`` XML output."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import IO, Union

from ..models import Host, Port

Source = Union[str, Path, IO[str], IO[bytes]]


def _text(element: ET.Element | None, attribute: str, default: str = "") -> str:
    if element is None:
        return default
    return element.get(attribute, default)


def _parse_port(port_element: ET.Element) -> Port | None:
    raw_number = port_element.get("portid")
    if not raw_number:
        return None
    try:
        number = int(raw_number)
    except ValueError:
        return None

    state = port_element.find("state")
    service = port_element.find("service")
    scripts = {
        _text(script, "id"): _text(script, "output")
        for script in port_element.findall("script")
        if script.get("id")
    }

    return Port(
        number=number,
        protocol=port_element.get("protocol", "tcp"),
        state=_text(state, "state", "unknown"),
        service=_text(service, "name"),
        product=_text(service, "product"),
        version=_text(service, "version"),
        extra_info=_text(service, "extrainfo"),
        scripts=scripts,
    )


def _parse_host(host_element: ET.Element) -> Host:
    status = host_element.find("status")

    address = ""
    for candidate in host_element.findall("address"):
        if candidate.get("addrtype") in ("ipv4", "ipv6"):
            address = candidate.get("addr", "")
            break
    if not address:
        address = _text(host_element.find("address"), "addr", "unknown")

    hostname = _text(host_element.find("hostnames/hostname"), "name")

    ports = []
    for port_element in host_element.findall("ports/port"):
        parsed = _parse_port(port_element)
        if parsed is not None:
            ports.append(parsed)
    ports.sort(key=lambda p: p.number)

    return Host(
        address=address,
        hostname=hostname,
        state=_text(status, "state", "unknown"),
        ports=ports,
    )


def parse_nmap_xml(source: Source, include_down: bool = False) -> list[Host]:
    """Parse an nmap XML file (or file object) into :class:`Host` objects.

    Args:
        source: path to the ``-oX`` output, or an open file object.
        include_down: keep hosts whose status is not ``up``.
    """
    root = ET.parse(source).getroot()
    hosts = [_parse_host(element) for element in root.iter("host")]
    if not include_down:
        hosts = [h for h in hosts if h.state == "up"]
    return hosts
