<div align="center">

<svg width="800" height="120" viewBox="0 0 800 120" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#0d1117"/>
      <stop offset="100%" style="stop-color:#161b22"/>
    </linearGradient>
    <linearGradient id="glow" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#58a6ff;stop-opacity:0"/>
      <stop offset="50%" style="stop-color:#58a6ff;stop-opacity:1"/>
      <stop offset="100%" style="stop-color:#58a6ff;stop-opacity:0"/>
    </linearGradient>
    <filter id="blur">
      <feGaussianBlur stdDeviation="3"/>
    </filter>
    <style>
      .title { font-family: 'Courier New', monospace; fill: #58a6ff; font-size: 28px; font-weight: bold; }
      .sub   { font-family: 'Courier New', monospace; fill: #8b949e; font-size: 13px; }
      .pulse { animation: pulse 2s ease-in-out infinite; }
      .scan  { animation: scan 3s linear infinite; }
      .fade1 { animation: fadein 0.5s ease forwards; }
      .fade2 { animation: fadein 0.5s ease 0.3s forwards; opacity:0; }
      .fade3 { animation: fadein 0.5s ease 0.6s forwards; opacity:0; }
      @keyframes pulse { 0%,100%{opacity:0.4} 50%{opacity:1} }
      @keyframes scan  { from{x:-200px} to{x:900px} }
      @keyframes fadein { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
    </style>
  </defs>
  <rect width="800" height="120" fill="url(#bg)" rx="8"/>
  <!-- scan line -->
  <rect class="scan" x="-200" y="0" width="200" height="120" fill="url(#glow)" opacity="0.08" filter="url(#blur)"/>
  <!-- dots grid -->
  <g opacity="0.12">
    <circle cx="30" cy="20" r="1.5" fill="#58a6ff" class="pulse"/>
    <circle cx="80" cy="50" r="1.5" fill="#58a6ff" class="pulse" style="animation-delay:0.4s"/>
    <circle cx="60" cy="90" r="1.5" fill="#58a6ff" class="pulse" style="animation-delay:0.8s"/>
    <circle cx="740" cy="30" r="1.5" fill="#58a6ff" class="pulse" style="animation-delay:0.2s"/>
    <circle cx="760" cy="80" r="1.5" fill="#58a6ff" class="pulse" style="animation-delay:0.6s"/>
    <circle cx="720" cy="100" r="1.5" fill="#58a6ff" class="pulse" style="animation-delay:1s"/>
  </g>
  <!-- border -->
  <rect width="800" height="120" fill="none" stroke="#30363d" stroke-width="1" rx="8"/>
  <!-- text -->
  <text x="400" y="52" text-anchor="middle" class="title fade1">bgp_analyzer</text>
  <text x="400" y="76" text-anchor="middle" class="sub fade2">BGP · RPKI · TLS Pivoting · APT Infrastructure Mapping</text>
  <text x="400" y="98" text-anchor="middle" class="sub fade3" style="fill:#3fb950;font-size:11px">
    ▸ Defensive Threat Intelligence Research
  </text>
</svg>

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-58a6ff?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-3fb950?style=flat-square)
![Data Sources](https://img.shields.io/badge/Data_Sources-15+-f78166?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Referenced-ff8c00?style=flat-square)

</div>

---

I built this after spending too many nights manually pivoting through threat infrastructure and thinking *"there has to be a better way."*

The short version: you give it an IP, a domain, or a file hash. It fans out across BGP routing tables, TLS certificate logs, passive DNS, and malware databases — and comes back with a cluster map of the infrastructure behind it. Think of it as the methodology in the [Hunt.io APT reports](https://hunt.io/blog) but automated and queryable from your terminal.

No magic, just chaining public data sources that most people look at separately.

---

## How the pivot chain works

The core idea is simple: **every piece of attacker infrastructure leaves traces across multiple independent data sources.** A C2 server has a TLS cert. That cert has SANs. Those SANs resolve to IPs. Those IPs share BGP prefixes. Those prefixes have RPKI records. And so on.

<div align="center">

<svg width="760" height="300" viewBox="0 0 760 300" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff" opacity="0.7"/>
    </marker>
    <marker id="arr2" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#3fb950" opacity="0.7"/>
    </marker>
    <style>
      .node { font-family: 'Courier New', monospace; font-size: 11px; }
      .box  { rx:6; ry:6; }
      .lbl  { font-family: 'Courier New', monospace; font-size: 10px; fill: #8b949e; }
      .edge { animation: dash 2s linear infinite; }
      @keyframes dash { to { stroke-dashoffset: -20; } }
      .pop1 { animation: popin 0.4s ease 0.1s both; }
      .pop2 { animation: popin 0.4s ease 0.3s both; }
      .pop3 { animation: popin 0.4s ease 0.5s both; }
      .pop4 { animation: popin 0.4s ease 0.7s both; }
      .pop5 { animation: popin 0.4s ease 0.9s both; }
      .pop6 { animation: popin 0.4s ease 1.1s both; }
      .pop7 { animation: popin 0.4s ease 1.3s both; }
      @keyframes popin { from{opacity:0;transform:scale(0.7)} to{opacity:1;transform:scale(1)} }
    </style>
  </defs>

  <!-- SEED -->
  <g class="pop1" transform="translate(310,20)">
    <rect width="140" height="34" fill="#1f2937" stroke="#f78166" stroke-width="1.5" rx="6"/>
    <text x="70" y="22" text-anchor="middle" fill="#f78166" font-family="monospace" font-size="12" font-weight="bold">SEED IOC</text>
  </g>
  <text x="380" y="70" text-anchor="middle" class="lbl">IP · Domain · Hash · ASN</text>

  <!-- TLS SAN -->
  <g class="pop2" transform="translate(60,120)">
    <rect width="145" height="50" fill="#0d1117" stroke="#58a6ff" stroke-width="1.2" rx="6"/>
    <text x="72" y="20" text-anchor="middle" fill="#58a6ff" font-family="monospace" font-size="11" font-weight="bold">TLS / crt.sh</text>
    <text x="72" y="36" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">SAN pivoting</text>
    <text x="72" y="48" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">cert history</text>
  </g>

  <!-- BGP -->
  <g class="pop3" transform="translate(240,120)">
    <rect width="145" height="50" fill="#0d1117" stroke="#58a6ff" stroke-width="1.2" rx="6"/>
    <text x="72" y="20" text-anchor="middle" fill="#58a6ff" font-family="monospace" font-size="11" font-weight="bold">BGP / RIPEstat</text>
    <text x="72" y="36" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">prefix history</text>
    <text x="72" y="48" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">origin changes</text>
  </g>

  <!-- RPKI -->
  <g class="pop4" transform="translate(420,120)">
    <rect width="145" height="50" fill="#0d1117" stroke="#58a6ff" stroke-width="1.2" rx="6"/>
    <text x="72" y="20" text-anchor="middle" fill="#58a6ff" font-family="monospace" font-size="11" font-weight="bold">RPKI / IRR</text>
    <text x="72" y="36" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">route validity</text>
    <text x="72" y="48" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">hijack detection</text>
  </g>

  <!-- Hash -->
  <g class="pop5" transform="translate(600,120)">
    <rect width="145" height="50" fill="#0d1117" stroke="#58a6ff" stroke-width="1.2" rx="6"/>
    <text x="72" y="20" text-anchor="middle" fill="#58a6ff" font-family="monospace" font-size="11" font-weight="bold">Hash Pivot</text>
    <text x="72" y="36" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">MalwareBazaar</text>
    <text x="72" y="48" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">ThreatFox</text>
  </g>

  <!-- CLUSTER -->
  <g class="pop6" transform="translate(200,230)">
    <rect width="360" height="40" fill="#0d1117" stroke="#3fb950" stroke-width="1.5" rx="6"/>
    <text x="180" y="17" text-anchor="middle" fill="#3fb950" font-family="monospace" font-size="11" font-weight="bold">Infrastructure Cluster Map</text>
    <text x="180" y="32" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="9">IPs · Domains · Hashes · ASN groups · C2 candidates</text>
  </g>

  <!-- Edges from seed -->
  <line x1="380" y1="54" x2="135" y2="120" stroke="#58a6ff" stroke-width="1" stroke-dasharray="4,3" opacity="0.5" marker-end="url(#arr)" class="edge"/>
  <line x1="380" y1="54" x2="312" y2="120" stroke="#58a6ff" stroke-width="1" stroke-dasharray="4,3" opacity="0.5" marker-end="url(#arr)" class="edge" style="animation-delay:-0.5s"/>
  <line x1="380" y1="54" x2="492" y2="120" stroke="#58a6ff" stroke-width="1" stroke-dasharray="4,3" opacity="0.5" marker-end="url(#arr)" class="edge" style="animation-delay:-1s"/>
  <line x1="380" y1="54" x2="672" y2="120" stroke="#58a6ff" stroke-width="1" stroke-dasharray="4,3" opacity="0.5" marker-end="url(#arr)" class="edge" style="animation-delay:-1.5s"/>

  <!-- Edges to cluster -->
  <line x1="132" y1="170" x2="310" y2="230" stroke="#3fb950" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#arr2)" class="edge" style="animation-delay:-0.3s"/>
  <line x1="312" y1="170" x2="340" y2="230" stroke="#3fb950" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#arr2)" class="edge" style="animation-delay:-0.8s"/>
  <line x1="492" y1="170" x2="420" y2="230" stroke="#3fb950" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#arr2)" class="edge" style="animation-delay:-1.2s"/>
  <line x1="672" y1="170" x2="520" y2="230" stroke="#3fb950" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#arr2)" class="edge" style="animation-delay:-1.7s"/>
</svg>

</div>

Each source feeds into the next. A domain found in a TLS cert gets BGP-checked. An IP found in BGP gets RPKI-validated. A hash from an open directory gets pivoted through malware databases. The graph keeps growing until you hit `max_depth`.

---

## The techniques, one by one

### 1. TLS Certificate SAN Pivoting

This is probably the most powerful single technique for mapping APT infrastructure.

When an attacker sets up a C2 server, they often reuse the same TLS certificate — or at minimum use the same CA, same key size, same Subject field pattern — across multiple servers. The **Subject Alternative Name (SAN)** field of a certificate lists all the domains the cert is valid for. If you find one domain, the cert often reveals five more.

The approach:
1. Connect to the target IP on port 443, grab the live certificate
2. Extract all SANs from the cert
3. Query [crt.sh](https://crt.sh) for the certificate history of each SAN — this reveals domains that shared certs historically, even if they don't anymore
4. Resolve each discovered domain, check if it routes through Cloudflare or directly to a backend IP
5. Queue all new IPs and domains for the next pivot depth

```
185.215.113.5 ──[TLS cert]──▶ SAN: c2panel.example.com
                                    update-service.net
                                    telemetry-cdn.com
                              └──[crt.sh history]──▶ 3 more domains from 2023
                                                      └──[DNS resolve]──▶ 3 new IPs
```

The key insight: **a Cloudflare IP in DNS ≠ attacker infrastructure**. When a domain resolves to Cloudflare, the real backend is hidden. When it resolves to a non-Cloudflare IP, that's your target. This technique has been documented in public APT reports against [MuddyWater](https://www.microsoft.com/en-us/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/) and [APT29](https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft).

---

### 2. BGP Route Analysis

BGP (Border Gateway Protocol) is the routing protocol that holds the internet together — and it was designed for trust, not security. This makes it a surprisingly rich source of threat intelligence.

The things I look at:

**Prefix churn** — Legitimate networks announce prefixes and leave them alone for months. Malicious infrastructure tends to announce prefixes, use them for a campaign, withdraw them, and move. High churn = suspicious. I pull this from [RIPEstat BGP updates](https://stat.ripe.net/docs/data_api).

**MOAS (Multiple Origin AS)** — A prefix being announced by two different ASNs simultaneously. This is a classic indicator of a BGP hijack — someone routing traffic through their own ASN to intercept it before it reaches the real destination. Cross-referencing with RPKI tells you which origin is legitimate.

**Multi-vantage-point consistency** — I check the prefix visibility from multiple [RIPE RIS collectors](https://ris.ripe.net/) around the world. A prefix that looks different from Tokyo vs. Frankfurt vs. São Paulo is suspicious.

<div align="center">

<svg width="640" height="180" viewBox="0 0 640 180" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .timeline-box { animation: slidein 0.6s ease both; }
      @keyframes slidein { from{opacity:0;transform:translateX(-20px)} to{opacity:1;transform:translateX(0)} }
    </style>
  </defs>
  <rect width="640" height="180" fill="#0d1117" rx="8" stroke="#30363d" stroke-width="1"/>
  <text x="20" y="25" font-family="monospace" font-size="11" fill="#8b949e">BGP prefix timeline — AS206349 / 185.215.113.0/24</text>

  <!-- timeline axis -->
  <line x1="30" y1="140" x2="620" y2="140" stroke="#30363d" stroke-width="1"/>
  <text x="30"  y="158" font-family="monospace" font-size="9" fill="#8b949e">Jan</text>
  <text x="148" y="158" font-family="monospace" font-size="9" fill="#8b949e">Mar</text>
  <text x="266" y="158" font-family="monospace" font-size="9" fill="#8b949e">May</text>
  <text x="384" y="158" font-family="monospace" font-size="9" fill="#8b949e">Jul</text>
  <text x="502" y="158" font-family="monospace" font-size="9" fill="#8b949e">Sep</text>

  <!-- announce/withdraw bars -->
  <rect x="40"  y="60" width="90" height="14" fill="#3fb950" opacity="0.8" rx="2" class="timeline-box"/>
  <rect x="140" y="60" width="12" height="14" fill="#f78166" opacity="0.9" rx="2" class="timeline-box" style="animation-delay:0.1s"/>
  <rect x="165" y="60" width="70" height="14" fill="#3fb950" opacity="0.8" rx="2" class="timeline-box" style="animation-delay:0.2s"/>
  <rect x="245" y="60" width="10" height="14" fill="#f78166" opacity="0.9" rx="2" class="timeline-box" style="animation-delay:0.3s"/>
  <rect x="265" y="60" width="40" height="14" fill="#3fb950" opacity="0.8" rx="2" class="timeline-box" style="animation-delay:0.4s"/>
  <rect x="315" y="60" width="8"  height="14" fill="#f78166" opacity="0.9" rx="2" class="timeline-box" style="animation-delay:0.5s"/>
  <rect x="335" y="60" width="25" height="14" fill="#3fb950" opacity="0.8" rx="2" class="timeline-box" style="animation-delay:0.6s"/>
  <rect x="370" y="60" width="8"  height="14" fill="#f78166" opacity="0.9" rx="2" class="timeline-box" style="animation-delay:0.7s"/>

  <!-- MOAS indicator -->
  <rect x="400" y="50" width="85" height="24" fill="#ff8c00" opacity="0.15" rx="2"/>
  <text x="442" y="66" text-anchor="middle" font-family="monospace" font-size="9" fill="#ff8c00">MOAS detected</text>
  <rect x="400" y="60" width="85" height="14" fill="#ff8c00" opacity="0.6" rx="2" class="timeline-box" style="animation-delay:0.8s"/>

  <rect x="500" y="60" width="60" height="14" fill="#3fb950" opacity="0.8" rx="2" class="timeline-box" style="animation-delay:0.9s"/>

  <!-- legend -->
  <rect x="40"  y="100" width="12" height="8" fill="#3fb950" rx="1"/>
  <text x="56"  y="108" font-family="monospace" font-size="9" fill="#8b949e">Announced</text>
  <rect x="130" y="100" width="12" height="8" fill="#f78166" rx="1"/>
  <text x="146" y="108" font-family="monospace" font-size="9" fill="#8b949e">Withdrawn</text>
  <rect x="220" y="100" width="12" height="8" fill="#ff8c00" rx="1"/>
  <text x="236" y="108" font-family="monospace" font-size="9" fill="#8b949e">MOAS / origin conflict</text>
</svg>

</div>

High-frequency announce/withdraw cycles on a prefix are a strong signal. Legitimate CDN providers and ISPs don't do this.

---

### 3. RPKI Validation

[RPKI (Resource Public Key Infrastructure)](https://rpki.cloudflare.com/) is the cryptographic system for authorizing BGP route origins. A **Route Origin Authorization (ROA)** says: "prefix X may only be announced by ASN Y."

An `RPKI INVALID` result means someone is announcing a prefix from an ASN that has no cryptographic authorization to do so. This can be:
- A BGP hijack (malicious)
- A misconfiguration (incompetent)
- A stale ROA (administrative failure)

In practice, the combination of `RPKI INVALID` + high churn + MOAS is a strong hijack indicator. I cross-validate with both [Cloudflare's RPKI validator](https://rpki.cloudflare.com/) and [RIPEstat](https://stat.ripe.net/docs/data_api) — they sometimes disagree, and the disagreement itself is interesting.

```
Prefix:   185.215.113.0/24
Expected: AS206349
Cloudflare RPKI: INVALID  ◀── no ROA covers this announcement
RIPEstat RPKI:   INVALID
MOAS:            AS44901 also announcing
Verdict:         HIGH CONFIDENCE HIJACK
```

---

### 4. Open Directory Scanning

This one is almost embarrassingly simple but alarmingly productive.

Threat actors set up web servers to stage payloads and exfiltrate data. They frequently leave directory listing enabled — either by accident or because they don't care. An exposed `/files/` directory on a C2 server is basically an open evidence locker.

What I look for:
- Apache/Nginx directory listing signatures in HTTP responses
- Suspicious file extensions in the listing: `.exe`, `.ps1`, `.sh`, `.elf`, `.dll`, `.bin`
- Files with names matching known malware families or toolkit names
- Common staging paths: `/tools/`, `/staging/`, `/upload/`, `/tmp/`, `/data/`

When I find a listing, I extract the file URLs and compute hashes for any downloadable artifacts — then pivot those hashes through MalwareBazaar and ThreatFox to see if they're known.

This technique is documented in [Recorded Future's infrastructure tracking methodology](https://www.recordedfuture.com/threat-intelligence-101) and was used publicly to track [MuddyWater staging servers](https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-targets).

---

### 5. APT Actor Infrastructure Mapping

The previous four techniques are all individual pivots. The real value comes from **running them recursively**, starting from known actor IOCs and letting the graph grow.

I maintain a small database of seed IOCs for documented APT groups — not my own research, just aggregated from public threat reports (Mandiant, MSTIC, Recorded Future, abuse.ch). The seeded IPs, domains, and hashes are the starting points. The engine then fans out:

```
Actor: MuddyWater
Seeds: 5 IPs, 4 domains, 0 hashes, 2 ASNs
       │
       ├─[depth 0]─ TLS pivot on seed IPs → 12 new domains
       │            BGP analysis on seed ASNs → 8 sample IPs
       │
       ├─[depth 1]─ TLS pivot on new domains → 6 more IPs
       │            Open dir scan → 2 open listings, 4 artifacts
       │
       └─[depth 2]─ Hash pivot on artifacts → 3 related C2 IPs
                    BGP clustering → 2 ASN clusters confirmed
```

By depth 2 you typically have a fairly complete picture of the infrastructure cluster. Anything sharing BGP space, TLS cert history, or artifact hashes is almost certainly operated by the same actor — or at minimum the same hosting provider serving them.

---

## Data sources

All free, all public — no scrapers, no unauthorized access.

| Source | What I use it for |
|--------|-------------------|
| [RIPEstat API](https://stat.ripe.net/docs/data_api) | BGP routing, prefix history, BGP updates |
| [Cloudflare RPKI](https://rpki.cloudflare.com/) | Route origin validation |
| [crt.sh](https://crt.sh/) | Certificate transparency historical data |
| [MalwareBazaar](https://bazaar.abuse.ch/) | File hash → malware family lookup |
| [ThreatFox](https://threatfox.abuse.ch/) | IOC pivot (hash → hosting infrastructure) |
| [Spamhaus DROP/ASN](https://www.spamhaus.org/drop/) | Known malicious network lists |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C2 IPs |
| [FireHOL](https://iplists.firehol.org/) | Aggregated IP blocklists |
| [AbuseIPDB](https://www.abuseipdb.com/) | Community abuse reports |
| [GreyNoise](https://www.greynoise.io/) | Scanner vs. targeted attacker classification |
| [OTX AlienVault](https://otx.alienvault.com/) | Threat pulses, correlated IOCs |
| [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/) | Historical DNS resolution data |
| [CAIDA AS-Rank](https://asrank.caida.org/) | AS relationship topology |
| [Shodan](https://shodan.io/) | Port banners, JA3 fingerprints, CVE exposure |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine malware analysis, graph pivoting |

---

## Output formats

Results are exported as:
- **JSON** — full graph for ingestion into SIEM / Elastic / Splunk
- **STIX 2.1** — standard threat intel sharing format, works with MISP / OpenCTI
- **HTML** — interactive D3.js force-directed graph, click any node to inspect

<div align="center">

<svg width="520" height="200" viewBox="0 0 520 200" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .nodecirc { animation: float 3s ease-in-out infinite; }
      @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)} }
    </style>
  </defs>
  <rect width="520" height="200" fill="#0d1117" rx="8" stroke="#30363d" stroke-width="1"/>
  <text x="260" y="22" text-anchor="middle" font-family="monospace" font-size="10" fill="#8b949e">D3.js graph output — example cluster</text>

  <!-- edges -->
  <line x1="260" y1="90"  x2="140" y2="130" stroke="#58a6ff" stroke-width="1" opacity="0.4" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1s" repeatCount="indefinite"/>
  </line>
  <line x1="260" y1="90"  x2="200" y2="155" stroke="#58a6ff" stroke-width="1" opacity="0.4" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1.2s" repeatCount="indefinite"/>
  </line>
  <line x1="260" y1="90"  x2="320" y2="155" stroke="#44cc44" stroke-width="1" opacity="0.4" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="0.9s" repeatCount="indefinite"/>
  </line>
  <line x1="260" y1="90"  x2="390" y2="130" stroke="#ff8c00" stroke-width="1" opacity="0.4" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1.4s" repeatCount="indefinite"/>
  </line>
  <line x1="140" y1="130" x2="100" y2="165" stroke="#58a6ff" stroke-width="1" opacity="0.3" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1.1s" repeatCount="indefinite"/>
  </line>
  <line x1="390" y1="130" x2="430" y2="165" stroke="#ff4444" stroke-width="1.5" opacity="0.5" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="0.8s" repeatCount="indefinite"/>
  </line>

  <!-- seed node -->
  <circle cx="260" cy="90" r="14" fill="#f78166" opacity="0.9" class="nodecirc" style="animation-delay:0s"/>
  <text x="260" y="94" text-anchor="middle" font-family="monospace" font-size="8" fill="#0d1117" font-weight="bold">SEED</text>

  <!-- IP nodes -->
  <circle cx="140" cy="130" r="9" fill="#4488ff" opacity="0.85" class="nodecirc" style="animation-delay:0.3s"/>
  <circle cx="200" cy="155" r="9" fill="#4488ff" opacity="0.85" class="nodecirc" style="animation-delay:0.6s"/>
  <circle cx="100" cy="165" r="8" fill="#4488ff" opacity="0.7" class="nodecirc" style="animation-delay:0.9s"/>

  <!-- domain nodes -->
  <circle cx="320" cy="155" r="8" fill="#44cc44" opacity="0.85" class="nodecirc" style="animation-delay:0.4s"/>

  <!-- C2 candidate -->
  <circle cx="390" cy="130" r="10" fill="#ff4444" opacity="0.9" class="nodecirc" style="animation-delay:0.7s"/>
  <text x="390" y="148" text-anchor="middle" font-family="monospace" font-size="8" fill="#ff4444">C2?</text>
  <circle cx="430" cy="165" r="8" fill="#ff4444" opacity="0.8" class="nodecirc" style="animation-delay:1s"/>

  <!-- CF-fronted -->
  <circle cx="310" cy="60" r="8" fill="#ff8c00" opacity="0.8" class="nodecirc" style="animation-delay:0.5s"/>
  <line x1="260" y1="90" x2="310" y2="68" stroke="#ff8c00" stroke-width="1" opacity="0.3" stroke-dasharray="3,2">
    <animate attributeName="stroke-dashoffset" from="0" to="-10" dur="1.3s" repeatCount="indefinite"/>
  </line>
  <text x="310" y="52" text-anchor="middle" font-family="monospace" font-size="8" fill="#ff8c00">CF-fronted</text>

  <!-- legend -->
  <circle cx="35"  cy="185" r="5" fill="#4488ff" opacity="0.85"/>
  <text x="45" y="189" font-family="monospace" font-size="8" fill="#8b949e">IP</text>
  <circle cx="75"  cy="185" r="5" fill="#44cc44" opacity="0.85"/>
  <text x="85" y="189" font-family="monospace" font-size="8" fill="#8b949e">Domain</text>
  <circle cx="130" cy="185" r="5" fill="#ff4444" opacity="0.9"/>
  <text x="140" y="189" font-family="monospace" font-size="8" fill="#8b949e">C2 candidate</text>
  <circle cx="210" cy="185" r="5" fill="#ff8c00" opacity="0.8"/>
  <text x="220" y="189" font-family="monospace" font-size="8" fill="#8b949e">CF-fronted</text>
  <circle cx="285" cy="185" r="5" fill="#f78166"/>
  <text x="295" y="189" font-family="monospace" font-size="8" fill="#8b949e">Seed</text>
</svg>

</div>

---

## MITRE ATT&CK coverage

The techniques this maps to, for anyone doing threat modeling or writing detection rules:

| Technique | ID | What this tool observes |
|-----------|-----|------------------------|
| Acquire Infrastructure | [T1583](https://attack.mitre.org/techniques/T1583/) | New ASN registrations, fresh prefix announcements |
| Compromise Infrastructure | [T1584](https://attack.mitre.org/techniques/T1584/) | RPKI INVALID on existing legitimate prefixes |
| Stage Capabilities | [T1608](https://attack.mitre.org/techniques/T1608/) | Open directory staging servers |
| Obtain Capabilities | [T1588](https://attack.mitre.org/techniques/T1588/) | Shared tooling across infrastructure (hash pivoting) |
| Web Service as C2 | [T1102](https://attack.mitre.org/techniques/T1102/) | Cloudflare-fronted C2 domains |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Port profile scoring |
| Domain Generation | [T1568](https://attack.mitre.org/techniques/T1568/) | Certificate pattern analysis |

---

## Further reading

A lot of this methodology is not original — I just connected the pieces. These are the papers and posts that shaped how I think about this:

- [Hunt.io — Hunting APT Infrastructure](https://hunt.io/blog) — the best public writing on this topic
- [Recorded Future — Infrastructure Tracking Methodology](https://www.recordedfuture.com/threat-intelligence-101)
- [Censys — Finding C2 Infrastructure](https://censys.com/how-attackers-hide-c2-infrastructure/)
- [Mandiant — APT29 Infrastructure Analysis](https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft)
- [RIPE NCC — RPKI FAQ](https://www.ripe.net/manage-ips-and-asns/resource-management/rpki/)
- [Cloudflare — Is BGP safe yet?](https://isbgpsafeyet.com/)
- [Feike Hacquebord — Pawn Storm Infrastructure Analysis](https://documents.trendmicro.com/assets/wp/wp-two-years-of-pawn-storm.pdf)

---

## Requirements

```
pip install requests
pip install dnspython     # recommended — better DNS resolution
pip install rich          # optional  — colored terminal output
```

No API keys required for basic functionality. Shodan and VirusTotal keys unlock additional enrichment.

---

<div align="center">
<sub>Built for defensive threat intelligence research. All data sources are public APIs.</sub>
</div>
