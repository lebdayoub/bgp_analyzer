"""
RPKI Validation — concept example
-----------------------------------
RPKI (Resource Public Key Infrastructure) lets ASN holders publish
Route Origin Authorizations (ROAs) — cryptographic statements saying
"prefix X is authorized to be announced by ASN Y."

An RPKI INVALID result means someone is announcing a prefix from an
ASN that has no authorization. Combined with MOAS detection, this
is a strong hijack indicator.

This queries both Cloudflare and RIPEstat and compares their answers.
"""

import json
import urllib.request
from urllib.parse import quote


def validate_cloudflare(asn: int, prefix: str) -> dict:
    """Query Cloudflare's RPKI validator."""
    url = f"https://rpki.cloudflare.com/api/v1/validity/AS{asn}/{quote(prefix, safe='')}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-research"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        validity = data.get("result", {}).get("validity", {})
        return {
            "source": "cloudflare",
            "status": validity.get("state", "unknown"),
            "description": validity.get("description", ""),
        }
    except Exception as e:
        return {"source": "cloudflare", "status": "error", "error": str(e)}


def validate_ripestat(asn: int, prefix: str) -> dict:
    """Query RIPEstat's RPKI validation endpoint."""
    url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={prefix}&prefix={prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-research"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        validations = data.get("data", {}).get("validations", [])
        if not validations:
            return {"source": "ripestat", "status": "not-found"}
        status = validations[0].get("validity", "unknown")
        return {"source": "ripestat", "status": status}
    except Exception as e:
        return {"source": "ripestat", "status": "error", "error": str(e)}


def check_moas(prefix: str) -> dict:
    """
    Multi-Origin AS detection via RIPEstat looking glass.
    A prefix announced by multiple ASNs simultaneously
    is a classic BGP hijack or route leak indicator.
    """
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={prefix}"
    origins = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-research"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        for rrc in data.get("data", {}).get("rrcs", []):
            for peer in rrc.get("peers", []):
                path = peer.get("as_path", "").split()
                if path:
                    origins.add(path[-1])
    except Exception:
        pass

    return {
        "prefix": prefix,
        "origins_seen": list(origins),
        "moas": len(origins) > 1,
    }


def analyze(asn: int, prefix: str) -> dict:
    print(f"[*] RPKI check: AS{asn} / {prefix}")

    cf = validate_cloudflare(asn, prefix)
    ripe = validate_ripestat(asn, prefix)
    moas = check_moas(prefix)

    consensus = "UNKNOWN"
    if cf["status"] == "valid" or ripe["status"] == "valid":
        consensus = "VALID"
    elif cf["status"] == "invalid" and ripe["status"] == "invalid":
        consensus = "INVALID"
    elif cf["status"] == "invalid" or ripe["status"] == "invalid":
        consensus = "INVALID_PARTIAL"
    elif cf["status"] == "not-found" and ripe["status"] == "not-found":
        consensus = "NOT_FOUND"

    hijack_score = 0
    if "INVALID" in consensus:
        hijack_score += 40
    if moas["moas"]:
        hijack_score += 35
    if consensus == "NOT_FOUND" and moas["moas"]:
        hijack_score += 20

    result = {
        "asn": asn,
        "prefix": prefix,
        "cloudflare": cf,
        "ripestat": ripe,
        "moas": moas,
        "consensus": consensus,
        "hijack_score": min(100, hijack_score),
        "verdict": "SUSPICIOUS" if hijack_score >= 50 else "CLEAN",
    }

    print(f"  Cloudflare: {cf['status']}")
    print(f"  RIPEstat:   {ripe['status']}")
    print(f"  MOAS:       {moas['moas']} (origins: {moas['origins_seen']})")
    print(f"  Consensus:  {consensus}  |  Hijack score: {hijack_score}")

    return result


if __name__ == "__main__":
    result = analyze(asn=206349, prefix="185.215.113.0/24")
    print(json.dumps(result, indent=2))
