"""
TLS SAN Pivoting — concept example
-----------------------------------
The idea: grab the live TLS certificate from a target IP/domain,
extract all Subject Alternative Names, then query crt.sh for the
historical cert log of each SAN. Every domain you find can be
resolved to new IPs, and each new IP can be SAN-pivoted again.

This is a minimal illustration of the technique — not a production tool.
"""

import ssl
import socket
import json
import urllib.request


def get_live_sans(host: str, port: int = 443) -> list[str]:
    """
    Open a TLS connection and extract SANs from the live certificate.
    Works even on self-signed certs (we're not verifying, just reading).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return [
                value
                for san_type, value in cert.get("subjectAltName", [])
                if san_type == "DNS"
            ]


def crtsh_history(domain: str) -> list[str]:
    """
    Query crt.sh for all domains that ever shared a certificate
    with this domain. Reveals infrastructure that rotated DNS
    but kept the same cert — common in long-running campaigns.
    """
    url = f"https://crt.sh/?output=json&q={domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-research"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        certs = json.loads(resp.read())

    seen = set()
    domains = []
    for cert in certs:
        for name in cert.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name and name not in seen:
                seen.add(name)
                domains.append(name)
    return domains


def pivot(seed: str) -> dict:
    print(f"[*] Pivoting from: {seed}")

    # Step 1: live cert SANs
    live_sans = []
    try:
        live_sans = get_live_sans(seed)
        print(f"  [+] Live SANs: {live_sans}")
    except Exception as e:
        print(f"  [-] TLS connect failed: {e}")

    # Step 2: crt.sh historical expansion
    all_domains = set(live_sans)
    for domain in live_sans[:5]:  # limit for demo
        try:
            historical = crtsh_history(domain)
            all_domains.update(historical)
        except Exception:
            pass

    # Step 3: resolve each domain to IPs
    discovered_ips = {}
    for domain in list(all_domains)[:20]:
        try:
            ip = socket.gethostbyname(domain)
            discovered_ips[domain] = ip
        except Exception:
            pass

    return {
        "seed": seed,
        "live_sans": live_sans,
        "total_domains_found": len(all_domains),
        "resolved_ips": discovered_ips,
    }


if __name__ == "__main__":
    # Example — replace with any IP or domain you're investigating
    result = pivot("185.220.101.47")
    print(json.dumps(result, indent=2))
