import json

from sagesec.kev import KEVCatalog
from sagesec.validator import extract_cve_ids, validate_cve_mentions


def test_kev_lookup(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({
        "catalogVersion": "test",
        "vulnerabilities": [{
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
        }],
    }))
    kev = KEVCatalog.from_file(path)
    assert len(kev) == 1
    assert kev.is_known_exploited("cve-2021-44228")  # case-insensitive
    assert not kev.is_known_exploited("CVE-1999-0001")
    assert kev.get("CVE-2021-44228").ransomware_use == "Known"


def test_extract_cve_ids():
    text = "See CVE-2024-6387 and cve-2023-38408, but not CVE-24-1."
    assert extract_cve_ids(text) == {"CVE-2024-6387", "CVE-2023-38408"}


def test_grounded_output_passes():
    report = validate_cve_mentions(
        "This OpenSSH version may be affected by CVE-2024-6387.",
        retrieved_cve_ids={"CVE-2024-6387"},
    )
    assert report.passed
    assert report.grounded == {"CVE-2024-6387"}


def test_fabricated_cve_is_caught():
    report = validate_cve_mentions(
        "Affected by CVE-2024-6387 and also CVE-2025-99999.",
        retrieved_cve_ids={"CVE-2024-6387"},
    )
    assert not report.passed
    assert report.fabricated == {"CVE-2025-99999"}
