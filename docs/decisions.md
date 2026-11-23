# Architecture decision records (initial)

- **ADR-001 — Go engine, TypeScript adapters.** No duplicate networking or rule logic in TypeScript. One canonical report format.
- **ADR-002 — modules/probes/rules.** Functional module is a unit of discovery, probe gathers evidence, rule decides pass/fail. `checks` reserved for non-technical prose.
- **ADR-003 — passive by default, explicit active consent.** Active profiles are always scoped and bounded; scope enforcement applies at connection time.
- **ADR-004 — independent coverage.** No successful score if failed collection conceals significant applicable rule evaluations; score is nullable.
- **ADR-005 — RDAP first, WHOIS fallback opt-in.** RDAP has structured events; personal contact data must be redacted.
- **ADR-006 — TLS includes certificate and negotiated cipher.** Full cipher inventory needs active enumeration. Renewal requires past observations.
- **ADR-007 — mail authentication as `email` module.** SPF/DKIM/DMARC depend on DNS observations but have independent semantics.
- **ADR-008 — public JSON v1 as primary extension point.** Do not over-generalize public Go interfaces prior to real external consumers.
- **ADR-009 — no interactive root menu in v1.** Empty invocation prints help, preserving stable scripts and non-TTY behavior.
- **ADR-010 — provider enrichment opt-in.** Location/ASN accuracy, provenance, licensing and privacy matter; missing provider means unknown.
