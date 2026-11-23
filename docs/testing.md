# Test strategy and performance budgets

## Layered testing

- **Unit:** deterministic rules, module parsers, canonicalization, severity mapping, scoring and config validation; table-driven fuzz targets for cookie, TXT, ASN.1, RDAP and URL inputs.
- **Fixture-driven integration:** `httptest.Server` with TLS certificates, fake DNS resolver, fake RDAP and GeoIP provider; no Internet requirement in CI.
- **Security regression:** DNS rebinding, private-address redirect, IPv6 bypass, CIDR classification, proxy bypass, decompression bomb, body size caps, malicious config/target input, scope escape, path traversal.
- **Contract:** example JSON validates schema, round-trips Go and TypeScript, stable rule IDs, SARIF 2.1.0 schema validation.
- **End-to-end:** built binary on Linux/macOS/Windows and Docker, JSON to file/stdout, exit status and signal handling.
- **Concurrency:** `go test -race ./...`, cancellation during every probe, scheduler fairness and duplicate suppression.
- **Performance:** benchmark 100 synthetic modules/observations with bounded memory, no unbounded goroutines, predictably enforce request budget and timeout.

## Acceptance gates

For each PR run `make verify` (format check, vet, unit tests, race tests, and build). Keep integration tests offline and fixture-based. The current repository is Go-only; schema validation is covered by the Go test suite. Use fixture time injection to remove clock-dependent flakiness. Multi-platform and container release smoke tests are future work.

Do not put external arbitrary domains in test suites. Integration tests that require live external services must be explicitly optional and isolated from merge gates.
