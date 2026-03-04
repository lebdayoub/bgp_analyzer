# Infrastructure Pivot Methodology

A practical reference for the techniques used in this project.

---

## 1. Start with what you have

Every investigation starts from at least one observable: an IP caught in a honeypot, a domain from a phishing report, a file hash from an endpoint alert. The goal is to expand that single point into a full infrastructure picture.

The key mental model: **attacker infrastructure is not isolated**. Every node leaves fingerprints across multiple independent data sources. Your job is to find them.

---

## 2. TLS certificates — the most underused source

TLS certificates are issued by third parties (CAs) and logged publicly in Certificate Transparency logs. An attacker can't avoid this.

**What to extract:**
- Subject Alternative Names (SANs) — every domain the cert covers
- Subject CN, O, OU fields — often reveal actor patterns
- Issuer — Let's Encrypt vs. commercial CA vs. self-signed means different things
- Validity window — short-lived certs suggest automation

**How to use it:**
1. Connect to port 443, grab live cert → extract SANs
2. Query `crt.sh` for historical certs matching any discovered SAN
3. Resolve each discovered domain
4. Skip Cloudflare IPs (proxy, not infrastructure). Flag direct IPs.

**Why it works:** Attackers regularly reuse cert infrastructure across campaigns. A C2 cert from March often shares SANs with infrastructure from the previous campaign in December.

---

## 3. BGP — routing tells stories

BGP was built for scalability and convergence, not for hiding what you're doing. The global routing table is public. Updates are logged by RIPE RIS and RouteViews in near-real-time.

**Signals:**

| Signal | What it means |
|--------|--------------|
| High announce/withdraw churn | Prefix used briefly then moved — typical of abuse-cycle infrastructure |
| MOAS (Multiple Origin AS) | Two different ASNs announcing same prefix simultaneously — possible hijack |
| New prefix from young ASN | Low historical routing depth — freshly registered for campaign |
| Sudden transit change | Infrastructure moved to new upstream, often after abuse complaint |

**RPKI adds cryptographic certainty.** If a prefix is `RPKI INVALID`, no Route Origin Authorization exists for that origin ASN. Combined with MOAS, this is a strong hijack signal.

---

## 4. Open directories — accidental evidence

Threat actors run web servers to stage payloads. A significant fraction leave Apache/Nginx directory listing enabled — either by accident or because OPSEC isn't their priority.

**What you find:**
- Compiled implants (`.exe`, `.elf`, `.dll`)
- Scripts (`.ps1`, `.sh`, `.bat`)
- Compressed toolkits (`.zip`, `.7z`)
- Sometimes entire campaign directories with dated versions

**How to use it:**
1. Scan target IP across common ports (80, 443, 8080, 8443, 3000, 5000, ...)
2. Probe staging paths: `/files/`, `/tools/`, `/upload/`, `/tmp/`, `/staging/`, `/data/`
3. Check response body for directory listing signatures (`Index of /`, `[PARENTDIR]`, etc.)
4. Extract all hrefs, filter by suspicious extension
5. Hash each artifact → pivot through malware databases

---

## 5. Hash pivoting — connecting samples across campaigns

A file hash is a permanent, unforgeable identifier. Once a sample is in a malware database, every IP or domain that ever hosted it is also recorded.

**Sources:**
- **MalwareBazaar** (abuse.ch) — malware family, file type, hosting URLs. Free, no key.
- **ThreatFox** (abuse.ch) — IOC mapping: hash → hosting IPs and domains. Free, no key.
- **VirusTotal** — multi-engine, relationships graph. Free tier is limited but useful.

**Pivot path:** hash → malware family → hosting IPs → other hashes from same infrastructure → more IPs

This is how you connect a sample found on one server to a cluster of C2 servers you didn't know about.

---

## 6. Chaining pivots recursively

The real power comes from running these techniques recursively, BFS-style:

```
depth 0:  seed IP → TLS pivot → 5 new domains
depth 1:  5 domains → DNS resolve → 3 new IPs
          3 IPs → open dir scan → 2 open listings → 4 artifacts
depth 2:  4 hashes → malware DB → 2 more hosting IPs
          2 IPs → BGP cluster → same /24, same ASN as seed
```

By depth 2-3 you typically have a fairly complete cluster. Stop expanding when:
- All new nodes resolve to Cloudflare/major CDNs
- All new hashes are clean (score 0 across all engines)
- Graph stops growing

---

## 7. Cluster confirmation

Multiple independent paths leading to the same ASN or IP block is strong confirmation. One signal can be coincidence. Three signals from different sources pointing to the same infrastructure is attribution-grade.

Signs you have a real cluster:
- Shared BGP prefix (same /24 or /20)
- Shared TLS certificate history
- Common malware family across hashes
- Consistent hosting provider / hosting country
- Correlated announce/withdraw timing across prefixes

---

## Data sources quick reference

| Source | Technique | Free |
|--------|-----------|------|
| RIPEstat | BGP updates, prefix history, RPKI | Yes |
| Cloudflare RPKI | Route origin validation | Yes |
| crt.sh | TLS cert transparency history | Yes |
| MalwareBazaar | Hash → malware family | Yes |
| ThreatFox | Hash/IP/domain → IOC pivot | Yes |
| Shodan | Port banners, JA3, CVE exposure | API key |
| VirusTotal | Multi-engine, relationship graph | API key |
