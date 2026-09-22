"""CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV is the highest-signal input to the future risk score: a CVE on this list
is known to be exploited in the wild, which matters more for prioritization
than a high CVSS number alone.

The catalog is a single JSON file. We download it once and query it locally,
so scans never depend on a live network call (and demos never fail because
a government website is slow).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_KEV_PATH = Path("data/kev.json")


@dataclass(frozen=True)
class KEVEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    required_action: str
    ransomware_use: str  # "Known" or "Unknown"


class KEVCatalog:
    def __init__(self, entries: dict[str, KEVEntry], catalog_version: str | None = None):
        self._entries = entries
        self.catalog_version = catalog_version

    @classmethod
    def from_file(cls, path: str | Path = DEFAULT_KEV_PATH) -> KEVCatalog:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries: dict[str, KEVEntry] = {}
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID", "").upper()
            if not cve_id:
                continue
            entries[cve_id] = KEVEntry(
                cve_id=cve_id,
                vendor=v.get("vendorProject", ""),
                product=v.get("product", ""),
                name=v.get("vulnerabilityName", ""),
                date_added=v.get("dateAdded", ""),
                required_action=v.get("requiredAction", ""),
                ransomware_use=v.get("knownRansomwareCampaignUse", "Unknown"),
            )
        return cls(entries, data.get("catalogVersion"))

    def __len__(self) -> int:
        return len(self._entries)

    def is_known_exploited(self, cve_id: str) -> bool:
        return cve_id.upper() in self._entries

    def get(self, cve_id: str) -> KEVEntry | None:
        return self._entries.get(cve_id.upper())


def download_kev(dest: str | Path = DEFAULT_KEV_PATH, timeout: int = 30) -> Path:
    """Fetch the latest KEV catalog. Writes atomically so a failed download
    never leaves a half-written file behind."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    # KEV_URL is a fixed https constant, never user-supplied (no SSRF risk).
    with urllib.request.urlopen(KEV_URL, timeout=timeout) as resp:
        tmp.write_bytes(resp.read())
    json.loads(tmp.read_text(encoding="utf-8"))  # validate before replacing
    tmp.replace(dest)
    return dest
