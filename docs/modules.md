# Modules, probes, rules and capability mapping

Use **module** for a functional area, **probe** for a network/data collection operation, **rule** for an evaluation, and **finding** for a reported issue. This supports reusing one DNS lookup across several rules and avoiding scores for informational enrichment data.

| User requirement | Module | Probes / data | Rules or interpretation | Default |
|---|---|---|---|---|
| Server location city/country/timezone | network | IP -> GeoIP provider/DB | Informational, approximate | Provider opt-in |
| Certificate subject/issuer/ASN.1/serial/fingerprint | tls | Certificate chain | Evidence; SHA-256 fingerprint | Passive |
| Certificate expires/renewed/NIST | tls | validity dates, policy mapping | Expiry rule; renewal unknown without history; documented NIST mapping | Passive |
| TLS ciphers/security issues | tls | Negotiated handshake; active enumeration | Legacy negotiated protocol/cipher; full list only active | Split |
| Domain registration, dates, ID, registrar, WHOIS server | domain | RDAP first; WHOIS optional fallback | Informational; near-expiry optional | Passive |
| Organization, ASN, server IP | network | DNS + ASN provider | Informational, source attributed | Passive/optional |
| Ports/open ports | network | Limited TCP connect probe | Open/closed/filtered not conflated | Active |
| DNS A/AAAA/CNAME/NS/MX/TXT | dns | Bounded queries | Typed evidence | Passive |
| Hostnames/domains/hosts | discovery | Explicit target plus optional passive discovery | In-scope verified only | Optional |
| DNS server IP/hostname | dns | NS names, A/AAAA of NS | Separate authoritative and recursive context | Passive |
| Traceroute | network | ICMP/UDP/TCP platform probe | Diagnostic, not security score | Active |
| Cookies | http | Set-Cookie headers | Secure, HttpOnly, SameSite, prefix rules | Passive |
| Headers | http | HTTP responses | Security header rules | Passive |
| Response time | http | HTTP request timing | Informational; no false uptime claim | Passive |
| Crawl rules/robots.txt | http | `/robots.txt` | Advisory only | Passive |
| security.txt and well-known | http | RFC 9116 path, bounded allowlist | Present/valid/expired; most well-known files informational | Passive |
| SPF/DKIM/DMARC and external mail services | email | TXT + MX; selectors configured | SPF/DMARC rules; DKIM scoped; service hints | Passive |
| DNSSEC DS/DNSKEY/RRSIG | dns | RR queries/validation | Claim validated only with crypto chain to trust anchor | Passive |

## Deferred modules

- `browser`: screenshot via sandboxed browser, social tags.
- `fingerprint`: tech stack with confidence and rule signatures.
- `reputation`: Google Safe Browsing (explicit key), Archive.org (third-party and limits).
- `sustainability`: carbon estimate with transparent assumptions.

Do not put all features under `ssl`: modern `tls` module owns certificates, handshake and cipher policy. Do not put SPF/DKIM/DMARC under `dns` merely because TXT carries them: `email` owns mail authentication semantics and depends on `dns`. Similarly response headers/cookies/robots/security.txt form one HTTP evidence family with distinct probes and rule groups.

## Initial rule catalog proposal

| ID | Severity default | Condition |
|---|---|---|
| `TLS-CERT-001` | critical | Expired certificate |
| `TLS-CERT-002` | medium | Certificate expires within policy window |
| `TLS-CERT-003` | high | Hostname mismatch |
| `TLS-CERT-004` | high | Untrusted/incomplete certificate chain |
| `TLS-PROTOCOL-001` | high | Deprecated negotiated TLS protocol |
| `HTTP-HEADER-001` | medium | HSTS absent on HTTPS |
| `HTTP-HEADER-002` | medium | CSP absent (context-aware) |
| `HTTP-HEADER-003` | low | `X-Content-Type-Options: nosniff` missing |
| `HTTP-COOKIE-001` | high | Sensitive HTTPS cookie lacks Secure |
| `HTTP-COOKIE-002` | medium | Session-like cookie lacks HttpOnly |
| `EMAIL-SPF-001` | medium | Invalid/multiple SPF records |
| `EMAIL-DMARC-001` | medium | DMARC missing |
| `EMAIL-DMARC-002` | low | DMARC policy `p=none` |
| `DNS-CAA-001` | info | No CAA record (informational by default) |
| `DNS-DNSSEC-001` | info | DNSSEC absent (policy-dependent) |

IDs are immutable after release. Don't reassign an ID to a different condition. Every rule includes applicability, dependencies, severity, source evidence, human explanation and remediation; non-applicable outcomes do not create severity findings. RFC/standards links belong in catalog metadata.

## Extended capability roadmap

Only DNS A/AAAA, HTTPS certificate/negotiated handshake evidence and HTTP response/HSTS are operational today. `TLS-CERT-001` and `HTTP-HEADER-001` are the implemented rule slice; the broader catalog above is a proposal. The following reconciles the extended catalog into the existing module boundaries. Names in the first column are planning labels, not accepted module IDs or CLI flags.

| Proposed capability | Owner | Planned collection and interpretation | Mode / gate |
|---|---|---|---|
| `target`, `config`, `runner` | Core engine | Target normalization, SSRF guards, defaults, environment/flag handling, bounded scheduling, diagnostics and exit gates | Local policy + bounded passive traffic |
| `scoring`, `report` | Scoring/output | Explainable score, coverage, category breakdowns, terminal/JSON and future SARIF | Local; grades deferred pending versioned policy |
| `headers-fp` | http / fingerprint | Server, Via, Alt-Svc and edge/CDN headers; delivery/protocol hints | Passive, informational heuristics |
| `tech` | fingerprint | Server, proxy, CDN, framework and CMS signatures from headers/cookies/TLS; bounded HTML/meta only with explicit body collection policy | Deferred; confidence and signature version required |
| `well-known` | http | Allowlisted security.txt, robots.txt and optional sitemap metadata | Bounded passive retrieval, exact scoped paths |
| `robots-sitemap` | http / discovery | Parse Allow/Disallow/Sitemap and advertised paths | Advisory only; fetching discovered links is active crawling |
| `rdns` | network / dns | PTR and forward-confirmed reverse DNS | Bounded passive DNS; no automatic target expansion |
| `ip-asn` | network | ASN, CIDR prefix, network operator and approximate region | Explicit configured provider/DB; source attribution |
| `bgp` | network | Announcing ASN, routing prefix and RPKI ROA validity | Optional provider; an invalid route alone does not prove hijacking |
| `cloud-fp` | network / fingerprint | Correlate IP prefixes, CNAME/NS and TLS/HTTP hints for cloud/CDN attribution | Optional sources; heuristic confidence |
| `dns-health` | dns | Authoritative NS, SOA, DNSKEY/DS and nameserver diversity | Bounded passive; AD bit is not independent DNSSEC validation |
| `mail-host` | email | MX, MTA-STS and TLS-RPT transport policy | Bounded passive DNS/HTTP, every dependency in scope |
| `host-cert` | tls | SAN/issuer and virtual host certificate overlap | Passive only on explicitly scoped endpoint; sweeping common ports requires active authorization |
| `ct` | discovery | CT issued names, wildcard certificates and historical SANs | Explicit external feed opt-in; names never expand scope |
| `whois` | domain | Registrar, registration/expiry, nameservers, redacted organization and ownership history | RDAP first, optional WHOIS fallback; history required for drift |
| `dns-enum` | discovery | Common-label resolution (www/api/staging/mail/vpn/dev/admin), CNAME/MX discovery | Active, explicitly authorized and bounded; no default enumeration |
| `crawl` | discovery / http | Same-origin link/script/form discovery, pages and third-party origin hints | Active, authorized scope, robots policy, page/depth/rate caps; do not fetch third-party origins automatically |
| `security-txt-verify` | http | RFC 9116 syntax, Expires, canonical URLs, contact and PGP fields | Bounded passive; never automatically fetch arbitrary contact/key URLs |
| `ip-rep` | reputation | Abuse/spam feeds, Tor exits, VPN/hosting/proxy classifications | Explicit optional API/feed; privacy, licensing and quota disclosure |
| `passive-ports` | network | Historical service telemetry without direct port probes | Explicit external provider opt-in; freshness/source, never current reachability claims |
| `probe` | http / network | CORS origin/credentials tests, TRACE, sensitive dotfile paths (.git/.env) | Deferred active probes; explicit authorization/scope, no credential attacks or secret body capture |
| `api`, `dashboard` | External consumers | Scan scheduling, history/score drift, alerts/webhooks, UI, organization auth/RBAC | Separate services consuming reports/SDK, outside scanner core |

### Profiles and safety reconciliation

The draft quick/full presets are deferred, not new `profile` enum values. A future quick selection would use core TLS/HTTP/DNS plus header hints; a future fuller passive selection could add DNS/mail health and explicitly configured enrichment/metadata. Neither preset may silently enable crawling, common-label DNS enumeration, arbitrary-port certificate collection, reputation feeds or external telemetry. No 1–3 second runtime guarantee is made.

The canonical profile contract remains `passive|active`. All active operations require the active profile, positive authorization and explicit scope, plus connection/request/time/rate limits. Active functionality is currently refused. External providers are separately opt-in even when they send no traffic to the target; disclose exchanged host/IP data, source, freshness, privacy, quotas and licensing. A discovered hostname, URL or port is evidence, never authorization to connect.
