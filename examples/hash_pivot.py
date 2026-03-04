"""
File Hash Pivoting — concept example
--------------------------------------
Given a file hash (MD5 / SHA1 / SHA256) found on an open directory
or passed from a threat feed, pivot through MalwareBazaar and ThreatFox
to find:
  - Malware family name
  - Other IPs / domains that hosted the same sample
  - Related hashes from the same campaign

This mirrors the Hunt.io technique of pivoting from a staged artifact
back to the full C2 infrastructure cluster.
"""

import json
import urllib.request
import urllib.error


def detect_hash_type(h: str) -> str:
    h = h.strip()
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "unknown")


def query_malwarebazaar(file_hash: str) -> dict:
    """
    MalwareBazaar — free, no key required.
    Returns malware family, file type, and known hosting URLs.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = f"query=get_info&hash={file_hash}".encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "threat-intel-research",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if data.get("query_status") != "ok":
            return {"found": False, "source": "malwarebazaar"}
        sample = data.get("data", [{}])[0]
        return {
            "found": True,
            "source": "malwarebazaar",
            "malware_family": sample.get("signature", "unknown"),
            "file_type": sample.get("file_type", ""),
            "file_size": sample.get("file_size", 0),
            "first_seen": sample.get("first_seen", ""),
            "tags": sample.get("tags", []),
            "delivery_method": sample.get("delivery_method", ""),
            "urls": [
                u.get("url", "") for u in sample.get("urls_from_same_campaign", [])
            ],
        }
    except Exception as e:
        return {"found": False, "source": "malwarebazaar", "error": str(e)}


def query_threatfox(file_hash: str) -> dict:
    """
    ThreatFox — free, no key required.
    Returns hosting IPs/domains associated with this hash.
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = json.dumps({"query": "search_hash", "hash": file_hash}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "threat-intel-research",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if data.get("query_status") != "ok":
            return {"found": False, "source": "threatfox"}
        iocs = data.get("data", [])
        hosting_ips, hosting_domains = [], []
        for ioc in iocs:
            ioc_val = ioc.get("ioc", "")
            ioc_type = ioc.get("ioc_type", "")
            if "ip" in ioc_type and ioc_val not in hosting_ips:
                # strip port if present (e.g. "1.2.3.4:4444")
                hosting_ips.append(ioc_val.split(":")[0])
            elif "domain" in ioc_type and ioc_val not in hosting_domains:
                hosting_domains.append(ioc_val)
        return {
            "found": bool(iocs),
            "source": "threatfox",
            "ioc_count": len(iocs),
            "hosting_ips": hosting_ips,
            "hosting_domains": hosting_domains,
            "malware_family": iocs[0].get("malware_printable", "") if iocs else "",
        }
    except Exception as e:
        return {"found": False, "source": "threatfox", "error": str(e)}


def pivot(file_hash: str) -> dict:
    h = file_hash.strip()
    hash_type = detect_hash_type(h)
    print(f"[*] Pivoting hash: {h[:16]}... ({hash_type})")

    mb = query_malwarebazaar(h)
    tf = query_threatfox(h)

    # merge hosting infrastructure from both sources
    all_ips = list({ip for ip in tf.get("hosting_ips", []) if ip})
    all_domains = list({d for d in tf.get("hosting_domains", []) if d})
    all_domains += [u for u in mb.get("urls", []) if u and u not in all_domains]

    family = mb.get("malware_family") or tf.get("malware_family") or "unknown"

    result = {
        "hash": h,
        "hash_type": hash_type,
        "malware_family": family,
        "malwarebazaar": mb,
        "threatfox": tf,
        "pivot_summary": {
            "hosting_ips": all_ips,
            "hosting_domains": all_domains,
            "total_infrastructure_nodes": len(all_ips) + len(all_domains),
        },
    }

    if all_ips:
        print(f"  [+] Hosting IPs:     {all_ips}")
    if all_domains:
        print(f"  [+] Hosting domains: {all_domains}")
    print(f"  [+] Malware family:  {family}")

    return result


if __name__ == "__main__":
    import sys
    # Example SHA256 — replace with any hash you're investigating
    sample_hash = sys.argv[1] if len(sys.argv) > 1 else \
        "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
    result = pivot(sample_hash)
    print(json.dumps(result, indent=2))
