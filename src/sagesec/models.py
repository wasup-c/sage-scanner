"""The finding schema: the contract between every pipeline stage.

Every stage (parser, CVE matcher, risk scorer, LLM explainer, frontend)
reads and writes these types. Keeping this contract stable and versioned is
what lets any one stage be rewritten later without touching the others.

Bump SCHEMA_VERSION whenever a field is added, removed, or changes meaning.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "0.1.0"


class ConfidenceTier(str, Enum):
    """How much we trust that a CVE actually applies to a detected service.

    This is the core idea of the project: scanner output is a hypothesis,
    not a fact. Version-based matching is noisy (banners can lie, and distros
    like Ubuntu backport security fixes without changing the version string),
    so every CVE match carries a tier the AI must explain to the user.

    Not used yet -- the CVE matcher (next milestone) will assign these.
    """

    CONFIRMED = "confirmed"  # exact CPE/version match, no distro-patch ambiguity
    PROBABLE = "probable"    # version is in an affected range, but OS may backport fixes
    POSSIBLE = "possible"    # product matched, version unknown or unparseable
    UNMATCHED = "unmatched"  # no reliable product identification at all


@dataclass(frozen=True)
class Service:
    """What Nmap believes is running on a port.

    Every text field here came from the *remote host* (service banners) and is
    attacker-controlled. Treat it as untrusted data everywhere downstream:
    escape it before rendering and never interpolate it into LLM instructions.
    """

    name: str | None = None        # e.g. "ssh"
    product: str | None = None     # e.g. "OpenSSH"
    version: str | None = None     # e.g. "8.9p1 Ubuntu 3ubuntu0.10"
    extrainfo: str | None = None   # e.g. "Ubuntu Linux; protocol 2.0"
    ostype: str | None = None
    method: str | None = None      # "probed" (real fingerprint) or "table" (port-number guess)
    conf: int | None = None        # Nmap's 0-10 confidence in the identification
    cpes: tuple[str, ...] = ()     # CPEs Nmap reported, e.g. "cpe:/a:openbsd:openssh:8.9p1"

    @property
    def is_port_table_guess(self) -> bool:
        """True when Nmap only guessed the service from the port number.

        "3306 is open, so it's probably MySQL" is not the same as actually
        fingerprinting MySQL. Beginners rarely know Nmap makes this
        distinction, so the UI and the AI should surface it.
        """
        return self.method == "table"


@dataclass(frozen=True)
class Finding:
    """One port on one host, plus whatever is known about it."""

    port: int
    protocol: str                  # "tcp" or "udp"
    state: str                     # "open", "closed", "filtered", "open|filtered", ...
    reason: str | None = None      # why Nmap chose that state, e.g. "syn-ack"
    service: Service | None = None


@dataclass(frozen=True)
class OSMatch:
    name: str
    accuracy: int


@dataclass
class Host:
    address: str
    addr_type: str                 # "ipv4", "ipv6", or "mac"
    status: str                    # "up" or "down"
    hostnames: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    os_matches: list[OSMatch] = field(default_factory=list)

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.state == "open"]


@dataclass
class ScanResult:
    scanner: str
    scanner_version: str | None
    args: str | None
    started: int | None            # unix timestamps from Nmap
    finished: int | None
    hosts: list[Host] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
