"""Command-line entry point for the existing recon modules."""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .dirfuzz import DirFuzzer
from .portscan import PortScanner
from .report import ReportWriter
from .subdomain import SubdomainScanner
from .utils import validate_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-o", "--output", default="report.json")
    for flag in ("all", "subdomains", "ports", "dirs"):
        parser.add_argument("--" + flag, action="store_true")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--rate-limit", type=float, default=.1)
    parser.add_argument("--wordlist", default="wordlists/common_dirs.txt")
    parser.add_argument("--shodan-key")
    args = parser.parse_args()
    if not validate_target(args.target):
        parser.error("target must be a domain name without a URL scheme")
    if not (args.all or args.subdomains or args.ports or args.dirs):
        parser.error("choose --all, --subdomains, --ports, or --dirs")
    if args.threads < 1 or args.timeout <= 0 or args.rate_limit < 0:
        parser.error("threads and timeout must be positive; rate-limit must be nonnegative")
    if (args.all or args.dirs) and not Path(args.wordlist).is_file():
        parser.error("wordlist not found; supply --wordlist with an existing file")
    common = dict(threads=args.threads, timeout=args.timeout, rate_limit=args.rate_limit)
    data = {"target": args.target, "timestamp": datetime.now(timezone.utc).isoformat()}
    if args.all or args.subdomains:
        data["subdomains"] = SubdomainScanner(args.target, shodan_key=args.shodan_key, **common).run()
    if args.all or args.ports:
        data["ports"] = PortScanner(args.target, **common).run()
    if args.all or args.dirs:
        data["directories"] = DirFuzzer(args.target, args.wordlist, **common).run()
    ReportWriter(args.output).save(data)
