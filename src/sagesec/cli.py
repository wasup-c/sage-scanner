"""Command-line interface.

The project starts as a CLI on purpose: the pipeline is the hard part, and
a frontend added now would just be rewritten later.

    sage profiles
    sage parse tests/fixtures/sample_scan.xml
    sage scan 10.10.10.10 --profile service
    sage kev-update
    sage kev-check CVE-2024-6387
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__
from .kev import DEFAULT_KEV_PATH, KEVCatalog, download_kev
from .models import ScanResult
from .parser import NmapParseError, parse_nmap_xml_file
from .scanner import PROFILES, ScanError, TargetNotAllowedError, run_scan


def _print_summary(result: ScanResult) -> None:
    for host in result.hosts:
        names = f" ({', '.join(host.hostnames)})" if host.hostnames else ""
        print(f"\nHost {host.address}{names} is {host.status}")
        if host.os_matches:
            best = max(host.os_matches, key=lambda m: m.accuracy)
            print(f"  OS guess: {best.name} ({best.accuracy}% accuracy)")
        if not host.open_findings:
            print("  No open ports found.")
        for f in host.open_findings:
            svc = f.service
            label = " ".join(p for p in (svc.product, svc.version) if p) if svc else ""
            name = svc.name if svc and svc.name else "unknown"
            note = "  [guessed from port number only]" if svc and svc.is_port_table_guess else ""
            print(f"  {f'{f.port}/{f.protocol}':<10} {name:<12} {label}{note}")


def _emit(result: ScanResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_summary(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sage", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("profiles", help="list available scan profiles")

    p_parse = sub.add_parser("parse", help="parse a saved Nmap XML file")
    p_parse.add_argument("file")
    p_parse.add_argument("--json", action="store_true", help="output the full finding schema")

    p_scan = sub.add_parser("scan", help="run a scan against an in-scope target")
    p_scan.add_argument("target")
    p_scan.add_argument("--profile", default="quick", choices=sorted(PROFILES))
    p_scan.add_argument("--json", action="store_true")

    sub.add_parser("kev-update", help="download the CISA KEV catalog")

    p_kev = sub.add_parser("kev-check", help="check whether a CVE is known exploited")
    p_kev.add_argument("cve_id")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s",
                        stream=sys.stderr)

    try:
        if args.command == "profiles":
            for p in PROFILES.values():
                raw = " (needs raw sockets)" if p.needs_raw_sockets else ""
                print(f"{p.id:<8} {p.description}{raw}")
        elif args.command == "parse":
            _emit(parse_nmap_xml_file(args.file), args.json)
        elif args.command == "scan":
            _emit(run_scan(args.profile, args.target), args.json)
        elif args.command == "kev-update":
            path = download_kev()
            print(f"KEV catalog saved to {path} ({len(KEVCatalog.from_file(path))} entries)")
        elif args.command == "kev-check":
            entry = KEVCatalog.from_file(DEFAULT_KEV_PATH).get(args.cve_id)
            if entry is None:
                print(f"{args.cve_id.upper()} is not in the KEV catalog.")
            else:
                print(f"{entry.cve_id}: KNOWN EXPLOITED -- {entry.name}")
                print(f"  Added: {entry.date_added}  Ransomware use: {entry.ransomware_use}")
                print(f"  Required action: {entry.required_action}")
    except (TargetNotAllowedError, ScanError, NmapParseError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
