from pathlib import Path

import pytest
from defusedxml import EntitiesForbidden

from sagesec.parser import NmapParseError, parse_nmap_xml_file, parse_nmap_xml_string

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample():
    return parse_nmap_xml_file(FIXTURES / "sample_scan.xml")


def test_scan_metadata(sample):
    assert sample.scanner == "nmap"
    assert sample.scanner_version == "7.95"
    assert sample.schema_version
    assert len(sample.hosts) == 1


def test_host_details(sample):
    host = sample.hosts[0]
    assert host.address == "10.10.10.30"
    assert host.status == "up"
    assert host.hostnames == ["ubuntu-srv.lab.internal"]


def test_only_open_ports_in_open_findings(sample):
    host = sample.hosts[0]
    assert [f.port for f in host.open_findings] == [22, 80, 3306]
    assert any(f.port == 8080 and f.state == "filtered" for f in host.findings)


def test_probed_service_keeps_version_and_cpes(sample):
    ssh = next(f for f in sample.hosts[0].findings if f.port == 22)
    assert ssh.service.product == "OpenSSH"
    # The Ubuntu package suffix is exactly what the future confidence-tier
    # logic needs to detect possible security backports. Don't strip it.
    assert "ubuntu" in ssh.service.version.lower()
    assert "cpe:/a:openbsd:openssh:8.9p1" in ssh.service.cpes
    assert not ssh.service.is_port_table_guess


def test_port_table_guess_is_flagged(sample):
    mysql = next(f for f in sample.hosts[0].findings if f.port == 3306)
    assert mysql.service.is_port_table_guess
    assert mysql.service.product is None


def test_to_dict_is_json_serializable(sample):
    import json

    json.dumps(sample.to_dict())


def test_rejects_non_nmap_xml():
    with pytest.raises(NmapParseError):
        parse_nmap_xml_string("<notnmap/>")


def test_rejects_malformed_xml():
    with pytest.raises(NmapParseError):
        parse_nmap_xml_string("<nmaprun><host>")


def test_blocks_entity_expansion_attack():
    billion_laughs = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<nmaprun>&lol2;</nmaprun>"""
    with pytest.raises(EntitiesForbidden):
        parse_nmap_xml_string(billion_laughs)


def test_hostile_banner_is_normalized_but_preserved():
    """The parser strips control characters (blocking log injection) but does
    NOT try to 'remove' XSS or prompt-injection text. Those need output
    encoding and prompt structure downstream -- string filtering at the parser
    can't reliably catch them, and pretending otherwise is false security."""
    result = parse_nmap_xml_file(FIXTURES / "malicious_banner.xml")
    svc = result.hosts[0].findings[0].service

    assert "\n" not in svc.version  # log injection neutralized
    assert svc.product == "<script>alert(1)</script>"  # still present: frontend must escape
    assert "Ignore all previous instructions" in svc.extrainfo  # LLM layer must isolate
