#!/usr/bin/env python3
"""HeaderShield: dependency-free HTTP security header auditor."""

from __future__ import annotations

import argparse
import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class Finding:
    level: str
    title: str
    detail: str
    points: int


RULES = (
    ("strict-transport-security", "HSTS", "Add max-age and includeSubDomains after validating subdomain readiness.", 15, "high"),
    ("content-security-policy", "Content-Security-Policy", "Add a restrictive CSP and tune it with report-only mode first.", 25, "high"),
    ("x-content-type-options", "X-Content-Type-Options", "Set X-Content-Type-Options: nosniff.", 10, "medium"),
    ("referrer-policy", "Referrer-Policy", "Prefer strict-origin-when-cross-origin or stricter.", 10, "medium"),
    ("permissions-policy", "Permissions-Policy", "Explicitly disable browser features your application does not need.", 10, "low"),
)


def fetch(url: str) -> tuple[str, dict[str, str]]:
    request = Request(url, headers={"User-Agent": "HeaderShield/1.0 (defensive audit)"})
    context = ssl.create_default_context()
    with urlopen(request, timeout=12, context=context) as response:
        return response.url, {key.lower(): value for key, value in response.headers.items()}


def evaluate(url: str, headers: dict[str, str]) -> tuple[int, list[Finding]]:
    headers = {key.lower(): value for key, value in headers.items()}
    findings: list[Finding] = []
    score = 0

    if url.startswith("https://"):
        score += 20
        findings.append(Finding("pass", "HTTPS in use", "The final URL uses HTTPS.", 20))
    else:
        findings.append(Finding("high", "HTTPS is not in use", "Redirect HTTP traffic to HTTPS before serving content.", 0))

    for key, label, advice, points, severity in RULES:
        if key in headers:
            score += points
            findings.append(Finding("pass", f"{label}: {headers[key]}", "Header found.", points))
        else:
            findings.append(Finding(severity, f"{label} is missing", advice, 0))

    csp = headers.get("content-security-policy", "")
    if "x-frame-options" in headers or "frame-ancestors" in csp:
        score += 10
        findings.append(Finding("pass", "Frame protection enabled", "X-Frame-Options or CSP frame-ancestors was found.", 10))
    else:
        findings.append(Finding("medium", "Frame protection is missing", "Use X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.", 0))

    return min(score, 100), findings


def status(score: int) -> str:
    return "Good baseline" if score >= 80 else "Needs attention" if score >= 50 else "High priority"


def render(url: str, score: int, findings: list[Finding], markdown: bool) -> str:
    if markdown:
        lines = [f"# HeaderShield report", f"**Target:** {url}", f"**Score:** {score}/100 — {status(score)}", "", "## Findings"]
        lines += [f"- **{item.level.upper()}** — {item.title}: {item.detail}" for item in findings]
        return "\n".join(lines)

    lines = [f"HeaderShield · {url}", f"Score: {score}/100 · {status(score)}", ""]
    for item in findings:
        lines.append(f"[{item.level.upper()}] {item.title}")
        lines.append(f"       {item.detail}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit HTTP security headers safely.")
    parser.add_argument("url", nargs="?", help="Public URL to audit")
    parser.add_argument("--headers-file", type=Path, help="JSON headers fixture for an offline demo")
    parser.add_argument("--format", choices=("text", "markdown"), default="text")
    parser.add_argument("--output", type=Path, help="Write report to a file")
    args = parser.parse_args()

    if args.headers_file:
        fixture = json.loads(args.headers_file.read_text(encoding="utf-8"))
        target, headers = fixture.get("url", "https://demo.local"), fixture["headers"]
    elif args.url:
        try:
            target, headers = fetch(args.url)
        except (HTTPError, URLError, TimeoutError) as error:
            raise SystemExit(f"Could not fetch target: {error}") from error
    else:
        parser.error("provide a URL or --headers-file examples/weak_headers.json")

    score, findings = evaluate(target, headers)
    report = render(target, score, findings, args.format == "markdown")
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
