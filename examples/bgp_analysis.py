"""
BGP Route Analysis — concept example
--------------------------------------
BGP was designed for trust, not security. This means the routing
table leaks a surprising amount of threat intelligence:

  - Prefix churn: announce → use for campaign → withdraw → move
  - MOAS: same prefix announced from two different ASNs simultaneously
  - Upstream changes: suddenly switching transit providers is suspicious
  - Visibility anomalies: prefix looks different from different regions

All data comes from the free RIPEstat API — no key required.
"""

import json
import urllib.request
from datetime import datetime, timedelta, timezone


RIPESTAT = "https://stat.ripe.net/data"


def _get(endpoint: str, params: dict) -> dict:
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{RIPESTAT}/{endpoint}/data.json?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "threat-intel-research"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read()).get("data", {})


def get_announced_prefixes(asn: int) -> list[str]:
    """What prefixes is this ASN currently announcing?"""
    data = _get("announced-prefixes", {"resource": f"AS{asn}"})
    return [p["prefix"] for p in data.get("prefixes", [])]


def get_bgp_updates(resource: str, hours: int = 48) -> dict:
    """
    Fetch BGP announce/withdraw events for a prefix or ASN.
    High churn (many withdrawals relative to announcements) is suspicious.
    """
    end   = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    data  = _get("bgp-updates", {
        "resource":  resource,
        "starttime": start.strftime("%Y-%m-%dT%H:%M"),
        "endtime":   end.strftime("%Y-%m-%dT%H:%M"),
    })
    updates      = data.get("updates", [])
    announced    = [u for u in updates if u.get("type") == "A"]
    withdrawn    = [u for u in updates if u.get("type") == "W"]
    flapping     = set(u.get("target_prefix","") for u in announced) & \
                   set(u.get("target_prefix","") for u in withdrawn)

    churn_score = 0
    if len(withdrawn) > 20:
        churn_score += 30
    if len(flapping) > 2:
        churn_score += 40
    if len(updates) > 100:
        churn_score += 20

    return {
        "resource":       resource,
        "period_hours":   hours,
        "total_updates":  len(updates),
        "announcements":  len(announced),
        "withdrawals":    len(withdrawn),
        "flapping_prefixes": list(flapping)[:10],
        "churn_score":    min(100, churn_score),
        "suspicious":     churn_score >= 40,
    }


def detect_moas(prefix: str) -> dict:
    """
    Multi-Origin AS detection via the RIPEstat looking glass.
    If more than one ASN is announcing the same prefix from
    different vantage points, something is wrong.
    """
    data    = _get("looking-glass", {"resource": prefix})
    origins = set()
    vantage_points = 0
    for rrc in data.get("rrcs", []):
        vantage_points += 1
        for peer in rrc.get("peers", []):
            path = peer.get("as_path", "").split()
            if path:
                origins.add(path[-1])

    return {
        "prefix":         prefix,
        "origins_seen":   list(origins),
        "vantage_points": vantage_points,
        "moas":           len(origins) > 1,
        "moas_score":     50 if len(origins) > 1 else 0,
    }


def get_routing_history(prefix: str, days: int = 30) -> dict:
    """
    How long has this prefix been in the routing table?
    Fresh prefixes (< 30 days) are higher risk.
    """
    data = _get("routing-history", {"resource": prefix, "max_rows": 50})
    by_time = data.get("by_origin", [])
    oldest  = None
    for entry in by_time:
        for ts_range in entry.get("timelines", []):
            t = ts_range.get("starttime", "")
            if t and (oldest is None or t < oldest):
                oldest = t
    age_days = None
    if oldest:
        try:
            first_seen = datetime.fromisoformat(oldest.replace("Z", "+00:00"))
            age_days   = (datetime.now(timezone.utc) - first_seen).days
        except Exception:
            pass
    return {
        "prefix":      prefix,
        "first_seen":  oldest,
        "age_days":    age_days,
        "fresh":       age_days is not None and age_days < 30,
    }


def analyze_asn(asn: int) -> dict:
    print(f"[*] BGP analysis for AS{asn}")

    prefixes = get_announced_prefixes(asn)
    print(f"  [+] Announced prefixes: {len(prefixes)}")

    bgp_updates = get_bgp_updates(f"AS{asn}")
    print(f"  [+] Updates (48h): {bgp_updates['total_updates']} "
          f"| churn_score={bgp_updates['churn_score']}")

    prefix_details = []
    for pfx in prefixes[:5]:   # limit for demo
        moas    = detect_moas(pfx)
        history = get_routing_history(pfx)
        prefix_details.append({
            "prefix": pfx,
            "moas":   moas["moas"],
            "origins": moas["origins_seen"],
            "age_days": history["age_days"],
            "fresh":  history["fresh"],
        })
        flag = " ⚠ MOAS" if moas["moas"] else ""
        age  = f"{history['age_days']}d" if history["age_days"] else "unknown"
        print(f"    {pfx:<22} age={age:>8}  {flag}")

    risk_score = bgp_updates["churn_score"]
    if any(p["moas"] for p in prefix_details):
        risk_score += 30
    if any(p["fresh"] for p in prefix_details):
        risk_score += 20

    return {
        "asn":              asn,
        "prefix_count":     len(prefixes),
        "bgp_updates":      bgp_updates,
        "prefix_details":   prefix_details,
        "risk_score":       min(100, risk_score),
        "verdict":          "SUSPICIOUS" if risk_score >= 50 else "CLEAN",
    }


if __name__ == "__main__":
    import sys
    target_asn = int(sys.argv[1]) if len(sys.argv) > 1 else 206349
    result = analyze_asn(target_asn)
    print(f"\n[+] Risk score: {result['risk_score']} — {result['verdict']}")
    print(json.dumps(result, indent=2))
