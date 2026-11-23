# Changelog

This project has not published a release. The entries below describe the current unreleased development state.

## Unreleased

### Added

- Go CLI commands, strict configuration loading, report v1 JSON validation, and version/build metadata.
- A scoped passive scan slice for public DNS A/AAAA, HTTPS certificate inspection, HTTP response/HSTS evaluation, coverage, and terminal/JSON output.
- Normal, short, and text version banners; structured terminal summaries, rule outcomes, findings, diagnostics, evidence, and UTC timing.
- Apache License 2.0 text, contributor and security policies, and GitHub Actions CI for formatting, vet, tests, race tests, and build.

### Changed

- Consolidated CLI output guidance in `docs/cli.md` and capability planning in `docs/modules.md`.
- Rewrote the README to document the implemented Go CLI and distinguish planned work from available functionality.

### Not implemented

Email, domain, ASN/GeoIP, and discovery probes; SARIF; TypeScript adapters; release packaging; and active probes remain future work. No public release binaries are available.
