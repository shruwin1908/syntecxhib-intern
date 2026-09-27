#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Reflected XSS / basic input-sanitization checker

⚠️  ONLY run this against systems you own or are explicitly authorized to
    test (e.g. DVWA, OWASP Juice Shop, a local test server). Scanning
    third-party sites without permission is illegal in most jurisdictions.

Usage:
    python scanner.py --url http://localhost/dvwa --max-pages 25
    python scanner.py --url http://localhost:3000 --cookie "PHPSESSID=abc123; security=low"
"""

import argparse
import sys
from urllib.parse import urlparse

import requests

from crawler import crawl
from injector import test_url_param, test_form
from report import save_json_report, save_text_report, print_summary


def build_session(cookie_header=None):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "WebVulnScanner/1.0 (educational project - authorized testing only)"
    })
    if cookie_header:
        session.headers.update({"Cookie": cookie_header})
    return session


def confirm_authorization(url):
    print(f"Target: {url}")
    answer = input(
        "Type YES to confirm you own this target or are explicitly authorized to test it: "
    ).strip()
    if answer != "YES":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Reflected XSS scanner (authorized targets only)")
    parser.add_argument("--url", required=True, help="Base URL of the target to scan")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl")
    parser.add_argument("--cookie", default=None, help="Cookie header, e.g. for authenticated DVWA sessions")
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout in seconds")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization prompt")
    parser.add_argument("--json-out", default="report.json", help="Path for the JSON report")
    parser.add_argument("--text-out", default="report.txt", help="Path for the text report")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print("Error: --url must start with http:// or https://")
        sys.exit(1)

    if not args.yes:
        confirm_authorization(args.url)

    session = build_session(args.cookie)

    print(f"\n[1/3] Crawling {args.url} (max {args.max_pages} pages)...")
    result = crawl(args.url, max_pages=args.max_pages, timeout=args.timeout, session=session)
    print(f"      Visited {len(result.visited)} page(s), "
          f"found {len(result.forms)} form(s), "
          f"{len(result.links_with_params)} link(s) with parameters.")

    all_findings = []

    print("[2/3] Testing URL parameters...")
    for link in result.links_with_params:
        for param_name in link["params"]:
            other = {k: v for k, v in link["params"].items() if k != param_name}
            all_findings.extend(
                test_url_param(session, link["url"].split("?")[0], param_name, other, timeout=args.timeout)
            )

    print("[3/3] Testing form fields...")
    for form in result.forms:
        all_findings.extend(test_form(session, form, timeout=args.timeout))

    json_path = save_json_report(all_findings, args.url, path=args.json_out)
    text_path = save_text_report(all_findings, args.url, path=args.text_out)

    print_summary(all_findings)
    print(f"\nReports written to:\n  {json_path}\n  {text_path}")


if __name__ == "__main__":
    main()
