# WASP

<p align="center">
  <img src="wasp-logo.png" alt="WASP logo: a bee inside a shield, with the WASP name" width="360">
</p>

WASP (Website Audit & Security Profiler) is a Go command-line tool for collecting a small, bounded set of public DNS, TLS, and HTTP security observations. It separates collected evidence from rule evaluations and reports incomplete coverage rather than treating missing evidence as a pass.

> **Status:** early development, pre-1.0. The current release implements scoped DNS A/AAAA lookups, HTTPS certificate inspection, HTTP response/HSTS evaluation, JSON and terminal reports, configuration validation, and report validation. Other catalog modules and capabilities described in the roadmap are not implemented. There are no published release binaries yet.

## Features

- Passive-by-default scans with explicit target scope and bounded execution.
- TLS certificate and negotiated-connection observations, basic HTTP response/HSTS checks, and DNS A/AAAA records.
- Stable rule outcomes, diagnostics, coverage, and versioned JSON reports.
- CLI commands for module/rule discovery, configuration validation, report validation, and build metadata.

WASP is an audit aid, not proof that a target is secure. Use it only on systems you own or have permission to assess. Even passive scans send network traffic.

## Requirements

- Go 1.25.0 or newer.

## Build and run

```bash
git clone https://github.com/caseypc/wasp.git
cd wasp
go test ./...
go build -o wasp ./cmd/wasp
./wasp --help
./wasp modules list
```

To scan a target you are authorized to assess:

```bash
./wasp scan example.com --modules tls,http,dns
```

Write machine-readable output to a file with:

```bash
./wasp scan example.com --modules tls,http,dns --format json --output report.json
./wasp report validate --file report.json
```

Current scans support the `tls`, `http`, and `dns` modules and `terminal` or `json` formats. SARIF, active scanning, crawling, release packaging, and external integrations are not available. See [the CLI reference](docs/cli.md) for flags, output behavior, and exit codes.

## Development

```bash
make fmt        # Format Go source
make fmt-check  # Check formatting without modifying files
make lint       # Run go vet
make test
make test-race
make verify     # Formatting check, vet, tests, race tests, and build
```

The test suite is designed to run offline. See [CONTRIBUTING.md](CONTRIBUTING.md) and [the testing guide](docs/testing.md).

## Documentation

- [CLI reference](docs/cli.md)
- [Configuration and scope](docs/configuration.md)
- [Modules and capability status](docs/modules.md)
- [Safety boundaries](docs/safety.md)
- [Report schema](docs/report-schema.md)

## License

WASP is licensed under the [Apache License 2.0](LICENSE).


