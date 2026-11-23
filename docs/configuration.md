# Configuration and scope

Default file `.wasp.yaml` in current directory (explicit `--config` overrides). All settings are type-checked; unexpected keys and unknown module IDs fail validation. CLI flags override file, environment variables are limited to documented non-sensitive options, with resolution precedence recorded in verbose diagnostics.

```yaml
schema_version: "1"
profile: passive
target:
  url: https://example.com
scope:
  include_hosts: [example.com]
  include_subdomains: false
  allowed_schemes: [https]
  allowed_ports: [443]
  follow_in_scope_redirects: true
modules: [tls, http, dns, email, domain, network]
limits:
  concurrency: 4
  total_timeout: 30s
  request_timeout: 8s
  max_requests: 50
  max_redirects: 3
  max_response_bytes: 1048576
policy:
  id: default-v1
  minimum_score_coverage: 0.80
  cert_expiry_warning_days: 30
  fail_on: high
email:
  dkim_selectors: []
providers:
  geoip: disabled
  asn: disabled
  rdap: enabled
report:
  format: terminal
  redact_sensitive: true
```

No unscoped discovery from wildcard patterns. Scope matching must operate on canonical host labels, not naive suffix matches (`evil-example.com` must never match `example.com`). `include_subdomains` is an explicit trust decision. `active` profile additionally requires `authorization.acknowledged: true` or CLI `--authorize`, plus scope manifest; do not accept `acknowledged` as proof of ownership.

The Go loader rejects unknown keys, multiple YAML documents, aliases, files over 1 MiB, and configurations over 20,000 YAML nodes. Missing scan defaults are filled after validation. The current scanner refuses `profile: active`; a positive acknowledgement alone never enables active traffic. When target scope omits schemes or ports, they default to the configured target's scheme and port.

Configuration v1 schema is provided at `schemas/config.v1.schema.json`; examples live in `examples/`. YAML-to-JSON mapping and strict unknown-field validation must be tested against the schema. Secrets should come from secret managers or masked environment variables, never committed YAML.

## CLI presentation and build metadata

The CLI's default User-Agent, version, commit, and build date are centralized in `internal/config/defaults.go`. Override build metadata at link time, for example:

```bash
go build -ldflags "-X github.com/caseypc/wasp/internal/config.Version=1.2.3 -X github.com/caseypc/wasp/internal/config.Commit=$(git rev-parse --short HEAD) -X github.com/caseypc/wasp/internal/config.BuildDate=$(date -u +%Y-%m-%d)" -o wasp ./cmd/wasp
```

Customize the HTTP User-Agent and terminal pass/fail labels with `WASP_USER_AGENT`, `WASP_LABEL_PASS`, and `WASP_LABEL_FAIL`. These values affect presentation or request identification, not scan scope or policy. Terminal status colors are enabled only for terminal output; set `NO_COLOR` (or `TERM=dumb`) to disable color. Normal, short and text banners are plain Unicode; see [CLI presentation](cli.md#terminal-presentation). JSON output remains free of terminal formatting.
