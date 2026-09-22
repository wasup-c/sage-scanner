"""Safe Nmap execution: validated targets, fixed profiles, no shell.

The unsafe pattern this module exists to prevent:

    user or LLM text -> shell string -> os.system()

Instead:

    user picks a profile ID + target -> validation -> argv list -> nmap

Three separate protections, each covering a different attack:

1. Scope allowlist: only addresses inside approved networks (your lab) can be
   scanned. Authorization enforced in code, not just in a README.
2. Strict target parsing: the target must parse as a single IP address.
   This blocks *argument injection* (a "target" like "-iL /etc/passwd" or
   "--script=..."), which is dangerous even without a shell.
3. No shell: subprocess gets a list of arguments, so shell metacharacters
   like ; | $() are just characters, never commands.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass

from .models import ScanResult
from .parser import parse_nmap_xml_string

logger = logging.getLogger("sagesec.audit")

# Default scope is the isolated lab network. Override with a comma-separated
# list, e.g. SAGE_ALLOWED_NETWORKS="10.10.10.0/24,10.20.0.0/24"
DEFAULT_ALLOWED_NETWORKS = "10.10.10.0/24"
SCAN_TIMEOUT_SECONDS = 600

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScanError(RuntimeError):
    pass


class TargetNotAllowedError(ValueError):
    pass


@dataclass(frozen=True)
class ScanProfile:
    id: str
    description: str
    args: tuple[str, ...]
    needs_raw_sockets: bool  # SYN and OS scans need CAP_NET_RAW (or root)


# Users choose from these IDs. They never supply raw Nmap flags.
PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        id="quick",
        description="Top 100 TCP ports, no service detection. Fast and low impact.",
        args=("-sT", "--top-ports", "100", "-T3"),
        needs_raw_sockets=False,
    ),
    "service": ScanProfile(
        id="service",
        description="Top 1000 TCP ports with service/version detection (-sV).",
        args=("-sT", "-sV", "--version-intensity", "5", "-T3"),
        needs_raw_sockets=False,
    ),
    "os": ScanProfile(
        id="os",
        description="Service/version plus OS detection (-O).",
        args=("-sS", "-sV", "-O", "-T3"),
        needs_raw_sockets=True,
    ),
}


def allowed_networks() -> list[IPNetwork]:
    raw = os.environ.get("SAGE_ALLOWED_NETWORKS", DEFAULT_ALLOWED_NETWORKS)
    return [ipaddress.ip_network(n.strip(), strict=True) for n in raw.split(",") if n.strip()]


def validate_target(target: str) -> IPAddress:
    """Return the target as a parsed IP, or raise if it is not allowed.

    Hostnames are rejected for now on purpose: a hostname can resolve to
    one address when we check it and another when Nmap scans it (DNS
    rebinding / time-of-check-time-of-use). Supporting hostnames safely means
    resolving once and scanning the resolved IP. That's a later feature.
    """
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise TargetNotAllowedError(
            f"target must be a single IP address, got {target!r}"
        ) from exc

    if not any(ip in net for net in allowed_networks()):
        raise TargetNotAllowedError(
            f"{ip} is outside the allowed scan scope. Only scan systems you "
            f"own or are authorized to assess."
        )
    return ip


def build_command(profile_id: str, target: str, nmap_path: str | None = None) -> list[str]:
    """Build the argv list. A pure function, so it's easy to unit test."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise ValueError(f"unknown profile {profile_id!r}; choose from {sorted(PROFILES)}")

    ip = validate_target(target)
    nmap = nmap_path or shutil.which("nmap")
    if nmap is None:
        raise ScanError("nmap not found on PATH")

    # "-oX -" writes XML to stdout. The target always goes last and is our
    # validated, re-serialized IP -- never the user's original string.
    return [nmap, *profile.args, "-oX", "-", str(ip)]


def run_scan(profile_id: str, target: str, initiated_by: str = "local-user") -> ScanResult:
    argv = build_command(profile_id, target)
    logger.info("scan start user=%s profile=%s target=%s", initiated_by, profile_id, argv[-1])

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
            shell=False,  # explicit, even though it's the default
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("scan timeout profile=%s target=%s", profile_id, argv[-1])
        raise ScanError(f"scan exceeded {SCAN_TIMEOUT_SECONDS}s") from exc

    if proc.returncode != 0:
        logger.warning("scan failed rc=%s target=%s", proc.returncode, argv[-1])
        raise ScanError(proc.stderr.strip() or f"nmap exited with {proc.returncode}")

    result = parse_nmap_xml_string(proc.stdout)
    open_count = sum(len(h.open_findings) for h in result.hosts)
    logger.info("scan done profile=%s target=%s open_ports=%d", profile_id, argv[-1], open_count)
    return result
