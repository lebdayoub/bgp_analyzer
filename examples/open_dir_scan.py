"""
Open Directory Scanner — concept example
-----------------------------------------
Threat actors frequently leave directory listing enabled on their
staging / C2 servers. An exposed /files/ or /tools/ directory is
basically an open evidence locker.

This scans an IP across common ports and paths, detects directory
listings, and extracts suspicious file artifacts for hash pivoting.
"""

import re
import socket
import urllib.request
import urllib.error
from urllib.parse import urljoin


PORTS = [80, 443, 8080, 8443, 8888, 3000, 5000]

DIR_SIGNATURES = [
    b"Index of /",
    b"Directory listing for",
    b"<title>Index of",
    b"[PARENTDIR]",
    b"Last modified</a>",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".sh", ".bat", ".elf",
    ".bin", ".msi", ".vbs", ".hta", ".jar",
    ".zip", ".7z", ".tar.gz",
}

STAGING_PATHS = [
    "/", "/files/", "/tools/", "/upload/",
    "/staging/", "/tmp/", "/data/", "/payload/",
    "/www/", "/pub/", "/share/",
]


def is_directory_listing(body: bytes) -> bool:
    body_lower = body.lower()
    return any(sig.lower() in body_lower for sig in DIR_SIGNATURES)


def extract_artifacts(body: bytes, base_url: str) -> list[dict]:
    """Pull hrefs from the listing and flag suspicious file extensions."""
    text = body.decode("utf-8", errors="replace")
    artifacts = []
    for match in re.finditer(r'href=["\']([^"\'?#]+)["\']', text, re.IGNORECASE):
        href = match.group(1).strip()
        if href.startswith("?") or href in ("../", "/"):
            continue
        # determine extension
        name = href.rstrip("/").split("/")[-1]
        ext = ""
        if "." in name:
            ext = "." + name.rsplit(".", 1)[-1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            artifacts.append({
                "name": name,
                "url": urljoin(base_url, href),
                "extension": ext,
            })
    return artifacts


def scan_ip(ip: str) -> dict:
    result = {
        "ip": ip,
        "open_directories": [],
        "artifacts": [],
        "total_listings": 0,
        "total_artifacts": 0,
    }

    for port in PORTS:
        scheme = "https" if port in (443, 8443) else "http"
        for path in STAGING_PATHS:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (threat-intel-research)"},
                )
                # short timeout — we're scanning many targets
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status != 200:
                        continue
                    body = resp.read(16384)   # 16 KB is enough to detect a listing
                    if not is_directory_listing(body):
                        continue

                    entry = {"url": url, "port": port, "path": path}
                    result["open_directories"].append(entry)
                    print(f"  [OPEN DIR] {url}")

                    arts = extract_artifacts(body, url)
                    result["artifacts"].extend(arts)
                    for a in arts:
                        print(f"    [artifact] {a['name']} ({a['extension']})")

            except (urllib.error.URLError, socket.timeout, OSError):
                # connection refused, timeout — normal for closed ports
                continue

    result["total_listings"] = len(result["open_directories"])
    result["total_artifacts"] = len(result["artifacts"])
    return result


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "185.220.101.47"
    print(f"[*] Scanning {target} for open directories...")
    out = scan_ip(target)
    print(f"\n[+] {out['total_listings']} open listings, {out['total_artifacts']} artifacts")
    print(json.dumps(out, indent=2))
