"""Parse Nmap XML output (-oX) into the finding schema.

Why XML instead of scraping terminal output: the human-readable format
changes between Nmap versions and truncates fields. The XML output is a
documented, stable, structured format.

Why defusedxml instead of the standard library: the XML we parse contains
data influenced by the scan target. The stdlib parser is vulnerable to
entity-expansion attacks ("billion laughs"). defusedxml refuses them.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree as SafeET

from .models import Finding, Host, OSMatch, ScanResult, Service

MAX_FIELD_LENGTH = 256


class NmapParseError(ValueError):
    """Raised when input is not valid Nmap XML."""


def clean_text(value: str | None) -> str | None:
    """Normalize an untrusted banner string.

    Strips control characters and caps length. This is NOT output encoding:
    the frontend must still escape on render, and the LLM layer must still
    keep this data out of the instruction channel. Defense in depth.
    """
    if value is None:
        return None
    # Replace control characters (newlines, escapes) with spaces, then
    # collapse runs of whitespace. A newline in a banner could otherwise
    # forge a fake line in our audit log.
    printable = "".join(ch if ch.isprintable() else " " for ch in value)
    collapsed = " ".join(printable.split())
    if not collapsed:
        return None
    return collapsed[:MAX_FIELD_LENGTH]


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _parse_service(el: Element | None) -> Service | None:
    if el is None:
        return None
    return Service(
        name=clean_text(el.get("name")),
        product=clean_text(el.get("product")),
        version=clean_text(el.get("version")),
        extrainfo=clean_text(el.get("extrainfo")),
        ostype=clean_text(el.get("ostype")),
        method=el.get("method"),
        conf=_int_or_none(el.get("conf")),
        cpes=tuple(c.text.strip() for c in el.findall("cpe") if c.text),
    )


def _parse_host(el: Element) -> Host:
    # A host can list several addresses (e.g. IPv4 plus MAC); prefer the IP.
    addresses = el.findall("address")
    ip = next((a for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), None)
    addr = ip if ip is not None else (addresses[0] if addresses else None)

    status_el = el.find("status")
    host = Host(
        address=addr.get("addr", "unknown") if addr is not None else "unknown",
        addr_type=addr.get("addrtype", "unknown") if addr is not None else "unknown",
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        hostnames=[
            name
            for h in el.findall("hostnames/hostname")
            if (name := clean_text(h.get("name")))
        ],
    )

    for port_el in el.findall("ports/port"):
        port = _int_or_none(port_el.get("portid"))
        if port is None:
            continue
        state_el = port_el.find("state")
        host.findings.append(
            Finding(
                port=port,
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                reason=state_el.get("reason") if state_el is not None else None,
                service=_parse_service(port_el.find("service")),
            )
        )

    for os_el in el.findall("os/osmatch"):
        host.os_matches.append(
            OSMatch(
                name=clean_text(os_el.get("name")) or "unknown",
                accuracy=_int_or_none(os_el.get("accuracy")) or 0,
            )
        )

    return host


def _parse_root(root: Element) -> ScanResult:
    if root.tag != "nmaprun":
        raise NmapParseError(f"expected <nmaprun> root element, got <{root.tag}>")

    finished_el = root.find("runstats/finished")
    result = ScanResult(
        scanner=root.get("scanner", "nmap"),
        scanner_version=root.get("version"),
        args=root.get("args"),
        started=_int_or_none(root.get("start")),
        finished=_int_or_none(finished_el.get("time")) if finished_el is not None else None,
    )
    result.hosts = [_parse_host(h) for h in root.findall("host")]
    return result


def parse_nmap_xml_string(xml_text: str) -> ScanResult:
    """Parse Nmap XML. Raises NmapParseError on malformed input.

    defusedxml's own exceptions (e.g. EntitiesForbidden) are allowed to
    propagate on purpose: a hostile document should fail loudly, not be
    silently treated as a parse error.
    """
    try:
        root = SafeET.fromstring(xml_text)
    except ParseError as exc:
        raise NmapParseError(f"invalid XML: {exc}") from exc
    return _parse_root(root)


def parse_nmap_xml_file(path: str | Path) -> ScanResult:
    return parse_nmap_xml_string(Path(path).read_text(encoding="utf-8"))
