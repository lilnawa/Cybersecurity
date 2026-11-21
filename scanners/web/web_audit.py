"""Audit HTTP security headers, TLS settings, cookies and server banners."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

_REPO_ROOT = next(
    (parent for parent in Path(__file__).resolve().parents if (parent / "common.py").is_file()),
    Path(__file__).resolve().parent,
)
sys.path.insert(0, str(_REPO_ROOT))

from common import (  # noqa: E402
    add_json_arg,
    add_output_dir_arg,
    build_report,
    print_error,
    save_report as write_report,
)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS and protects against protocol downgrade/MITM.",
    "Content-Security-Policy": "Restricts resource sources to reduce XSS and injection risks.",
    "X-Frame-Options": "Prevents framing to help mitigate clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing ('nosniff').",
    "Referrer-Policy": "Controls referrer information sent across origins.",
    "Permissions-Policy": "Restricts browser APIs (camera, microphone, geolocation, etc.).",
}

SENSITIVE_HEADERS = ["server", "x-powered-by", "x-aspnet-version"]


def check_tls_info(hostname: str, port: int = 443) -> dict:
    info = {"supported": False, "protocol": None, "cipher": None, "cert_expiry": None, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["supported"] = True
                info["protocol"] = ssock.version()
                cipher = ssock.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["cert_expiry"] = cert.get("notAfter") if cert else None
    except Exception as exc:
        info["error"] = str(exc)
    return info


def analyze_cookies(raw_cookies: list[str]) -> list[dict]:
    findings = []
    for idx, cookie in enumerate(raw_cookies, start=1):
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0] if parts and "=" in parts[0] else f"cookie_{idx}"
        lower_flags = [p.lower() for p in parts[1:]]

        has_httponly = any(f == "httponly" for f in lower_flags)
        has_secure = any(f == "secure" for f in lower_flags)
        samesite = next((f.split("=", 1)[1] for f in lower_flags if f.startswith("samesite=")), None)

        issues = []
        if not has_httponly:
            issues.append("Missing HttpOnly flag")
        if not has_secure:
            issues.append("Missing Secure flag")
        if not samesite:
            issues.append("Missing SameSite attribute")

        findings.append({
            "name": name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite,
            "issues": issues,
        })
    return findings


def audit_target(target: str) -> dict:
    if not target or not target.strip():
        raise ValueError("target must be a non-empty URL or hostname")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        target,
        headers={"User-Agent": "Nawa-WebAuditor/2.0"},
    )

    headers = {}
    status_code = None
    final_url = target
    fetch_error = None

    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            status_code = resp.status
            final_url = resp.geturl()
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        final_url = exc.geturl() or target
        headers = {k.lower(): v for k, v in exc.headers.items()}
    except Exception as exc:
        fetch_error = str(exc)

    missing_headers = []
    present_headers = {}
    for h_name, desc in SECURITY_HEADERS.items():
        val = headers.get(h_name.lower())
        if val:
            present_headers[h_name] = val
        else:
            missing_headers.append({"header": h_name, "reason": desc})

    exposed_banners = {}
    for s_hdr in SENSITIVE_HEADERS:
        if s_hdr in headers:
            exposed_banners[s_hdr] = headers[s_hdr]

    raw_set_cookie = headers.get("set-cookie", "")
    cookie_list = [c for c in raw_set_cookie.split("\n") if c.strip()] if raw_set_cookie else []
    cookies_audit = analyze_cookies(cookie_list)

    tls_info = check_tls_info(hostname, 443 if parsed.scheme == "https" else port)

    score = len(present_headers)
    max_score = len(SECURITY_HEADERS)
    summary = (
        f"Audited {final_url}: {score}/{max_score} security headers present, "
        f"{len(missing_headers)} missing"
    )
    if fetch_error:
        summary += f"; fetch failed: {fetch_error}"

    return build_report(
        "web_audit",
        summary=summary,
        input_target=target,
        final_url=final_url,
        http_status=status_code,
        fetch_error=fetch_error,
        is_https=final_url.startswith("https://"),
        header_score=f"{score}/{max_score}",
        present_headers=present_headers,
        missing_headers=missing_headers,
        exposed_banners=exposed_banners,
        cookies=cookies_audit,
        tls=tls_info,
    )


def save_report(report: dict, output_dir: str | None = None) -> str:
    return write_report(report, output_dir, prefix="web_audit")


def print_summary(report: dict, report_path: str) -> None:
    print("\n================ WEB SECURITY AUDIT ================")
    print(f"Target       : {report['final_url']}")
    print(f"HTTP Status  : {report['http_status']}")
    print(f"HTTPS Active : {'YES' if report['is_https'] else 'NO'}")
    print(f"Header Score : {report['header_score']}")

    if report["fetch_error"]:
        print(f"Fetch Error  : {report['fetch_error']}")

    tls = report["tls"]
    print("\n--- TLS / Certificate ---")
    if tls["supported"]:
        print(f"Protocol     : {tls['protocol']}")
        print(f"Cipher       : {tls['cipher']}")
        print(f"Cert Expires : {tls['cert_expiry']}")
    else:
        print(f"TLS Check    : Not available ({tls['error']})")

    print("\n--- Missing Security Headers ---")
    if not report["missing_headers"]:
        print("None! All core security headers are present.")
    else:
        for item in report["missing_headers"]:
            print(f"[!] {item['header']} -> {item['reason']}")

    print("\n--- Exposed Version/Server Banners ---")
    if not report["exposed_banners"]:
        print("None detected.")
    else:
        for key, value in report["exposed_banners"].items():
            print(f"[!] {key}: {value}")

    print("\n--- Cookie Flags ---")
    if not report["cookies"]:
        print("No Set-Cookie headers observed.")
    else:
        for cookie in report["cookies"]:
            status = "OK" if not cookie["issues"] else ", ".join(cookie["issues"])
            print(f"  * {cookie['name']}: {status}")

    print(f"\nReport saved : {report_path}")
    print("====================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_audit.py",
        description="Audit HTTP headers, TLS/certificate details, cookie flags and server banners.",
        epilog="Example: python3 web_audit.py https://example.com",
    )
    parser.add_argument("target", help="URL or hostname to audit")
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = audit_target(args.target)
        report_path = save_report(report, args.output_dir)
    except (ValueError, OSError) as exc:
        print_error(str(exc))
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
