# Security boundaries and responsible scanning

## Authorization and modes

`passive` is the default: small, bounded ordinary DNS/TLS/HTTP lookups, RDAP and explicitly configured enrichment. **Passive does not mean zero traffic or zero impact**: avoid surprising requests and respect site policies. Active probes (port scan, cipher sweep, traceroute, crawling, broad host enumeration) require `--profile active --authorize` and a target scope manifest; CLI authorization flag is an acknowledgement, not proof of legal permission.

## Egress and SSRF controls (must be built first)

- Public-routable target IPs only by default; block loopback, RFC1918, link-local, ULA, IPv4/IPv6 metadata, multicast, reserved and special-use ranges.
- Resolve and validate all A/AAAA results; connect to validated addresses to defeat DNS rebinding/TOCTOU; verify SNI/Host behavior; enforce restrictions for every redirect and every fresh connection.
- No redirect from scoped target to an unscoped origin; handle alternate protocols/ports, punycode, IPv4-mapped IPv6, dotted/decimal IP representations.
- Disable environment proxy inheritance unless explicitly and safely configured; reject credential-bearing target URLs by default.
- Set limits for total requests, response bytes, redirect depth, DNS recursion, TLS handshake, runtime, and concurrency; rate limit per host and globally.
- No shell invocation with target-derived data; use Go networking libraries and parameterized subprocess APIs only when unavoidable.
- Don't reuse HTTP cookies between domains; don't send credentials or follow auth challenges automatically; avoid collecting response bodies unless needed and bounded.
- Default to no cloud upload. Redact cookie contents, authorization headers, RDAP PII, secrets in DNS TXT, tokens and internal stack traces from reports and logs.
- Store artifacts with restrictive permissions; JSON reports can contain IP/host metadata even after redaction.

## Capabilities with external dependencies

RDAP and GeoIP can be inaccurate/incomplete/redacted. Optional external source providers must disclose data exchanged, quota requirements and privacy policy. Geolocation is approximate. DNSSEC `AD` bit is not equivalent to independent full validation. SPF parsing requires recursive lookup budget. DKIM cannot be comprehensively enumerated without known selectors. Full cipher support needs active handshake attempts.

## Threat-model scenarios to test

DNS rebinding, malicious redirects, open-redirects to cloud metadata, oversized HTTP/TXT responses, gzip/decompression bombs, malformed certificates/ASN.1, IDN homographs, IPv6 bypass, environment proxy bypass, TLS trust failures, error messages leaking secrets, YAML bombs/aliases, untrusted filenames and path traversal, malicious RDAP response, rate-limit evasion, CI action injection and supply-chain substitution.

## Disclosure

Treat tool vulnerabilities separately from findings on scanned domains. See the root `SECURITY.md` for the current disclosure guidance; maintainers should enable GitHub private vulnerability reporting before public launch.
