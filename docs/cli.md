# CLI specification

## Recommended top-level commands

| Command | Description |
|---|---|
| `wasp scan <target>` | Audit a URL or domain |
| `wasp modules list` / `wasp modules show <id>` | Inspect collection domains and passive/active requirements |
| `wasp rules list` / `wasp rules show <id>` | Inspect stable evaluation rules and remediation |
| `wasp config init` / `wasp config validate` | Create and validate YAML |
| `wasp report validate` | Validate an existing JSON report |
| `wasp version` | Version/build/schema metadata |
| `wasp completion <shell>` | Generate Cobra completion |

Use `modules` in place of `checks` for feature selection and `rules` for findings logic. `wasp checks list` may be supported as a deprecated alias with an explanation, but do not make it the canonical interface.

## Scan flags

```text
--config .wasp.yaml        optional YAML policy
--profile passive         passive|active; default passive
--modules tls,http,dns     supported comma-separated module IDs
--exclude-modules ...     optional exclusion
--format terminal         terminal|json|sarif
--output -                 stdout or exact output filepath (0600, no overwrite)
--fail-on high            none|low|medium|high|critical
--min-coverage 0.80       CI coverage gate [0,1]
--concurrency 4           total concurrent probes [1,64]
--timeout 30s             overall deadline
--request-timeout 8s      bounded per network operation
--max-requests 50         maximum total outbound requests
--authorize               required for all active operations
--scope-file scope.yaml   explicit in-scope host/protocol/ports/paths
--tls-enumerate-ciphers   active-only; requires TLS module
--ports 80,443            active-only; requires network module
--verbose                 diagnostics only, no secrets
--no-color                deterministic terminal output
--force                    atomically replace an existing output file
```

Validate incompatible options before network activity. Flags override configuration in a documented order. CLI URI target input is an origin; by default do not follow redirects off-origin unless they remain in scope. A hostname-only target implies HTTPS for HTTP/TLS inspection and domain-scoped DNS; record normalization in report.

## Behavior and exit codes

| Code | Meaning |
|---|---|
| `0` | Completed scan with all configured gates passed |
| `1` | Findings breached `--fail-on` threshold |
| `2` | Usage/configuration error |
| `3` | Scan runtime error or insufficient coverage below requested minimum |
| `4` | Explicit security/scope denial |

Exit gate precedence: scope denial > usage > runtime/coverage > findings threshold > success. A scan with partial observations can still be emitted with exit `3`. Always keep JSON/SARIF stdout clean; diagnostics and progress go to stderr. `--output` writes atomically to a user-specified path (permissions `0600` where relevant), never overwrites by default without `--force`.

## Unknown command and empty invocation

`wasp` prints help and exits 0; `wasp --help` prints help and exits 0. `wasp nonsense` or `wasp --nonsense` emits an actionable `unknown command/flag` error and appropriate command usage, exits 2. Cobra's built-in help should be retained; a numbered interactive menu is a separate future `wasp interactive` command, never a mandatory non-TTY experience.

## Terminal presentation

Banners share the injected build version (default `0.1.0`). `wasp version` uses the normal banner; `wasp version --banner short` and `wasp version --banner text` select the other forms. Version output also includes commit, build date, and report schema metadata. Banners are plain Unicode with no ANSI styling.

Normal:
```text
▗▖ ▗▖ ▗▄▖  ▗▄▄▖▗▄▄▖
▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌
▐▌█▐▌▐▛▀▜▌ ▝▀▚▖▐▛▀▘
▐▙█▟▌▐▌ ▐▌▗▄▄▞▘▐▌ v.0.1.0
```

Short:
```text
╻ ╻┏━┓┏━┓┏━┓
┃╻┃┣━┫┗━┓┣━┛
┗┻┛╹ ╹┗━┛╹ v.0.1.0
```

Text: `WASP (Website Audit & Security Profiler) v0.1.0`.

Terminal reports start with the short banner and end with the text banner. They show target normalization, UTC RFC3339 start/stop times and elapsed milliseconds, followed by these sections:

- `[!] SUMMARY`: scan status, counts for all six rule outcomes, score eligibility and overall coverage. A missing score is `n/a` with its reason; no letter grades or invented module scores are displayed.
- `[!] RULE EVALUATIONS`: canonical rule IDs, resource and exact outcome. Only evaluated passes use PASS; unknown/error/not_run/not_applicable remain distinct.
- `[!] OBSERVATIONS`: collection status by module/probe, separate from rule results.
- `[!] FINDINGS`: violations with severity, rule ID, title, detail and remediation. Empty findings say `None reported`, which does not imply a successful audit.
- `[!] DIAGNOSTICS`: collection failures with module/probe and error code.
- `[!] EVIDENCE`: available HTTP response/headers, TLS connection/certificate and DNS A/AAAA evidence. Only observed data is displayed; unavailable fields are omitted.

For example, an HTTP-only partial scan may include:

```text
[!] SUMMARY
  ├─ Status: partial
  ├─ Rules: 0 passed, 0 failed, 1 unknown, 0 error, 0 not run, 0 not applicable
  ├─ Score: n/a (insufficient_evidence)
  └─ Coverage: 0% (0/1)

[!] RULE EVALUATIONS
  [UNKNOWN] HTTP-HEADER-001  https://example.com:443

[!] FINDINGS (0)
  None reported
```

Selection and progress go to stderr: `[!] Target`, `[!] Modules: ... | Mode: passive`, then per-module collection status and diagnostics. Collection success never asserts that security rules passed. Reports go to stdout or the selected output file. JSON receives no banners, color or progress on stdout; terminal artifact files contain no ANSI colors.

PASS/FAIL labels are customizable with `WASP_LABEL_PASS` and `WASP_LABEL_FAIL`. Status colors appear only on terminal streams; `NO_COLOR` or `TERM=dumb` disables ANSI colors. The layout also works when redirected. Text formatting is for people; automation must consume versioned JSON.

## Current implementation

The flag list above includes planned interfaces. Current scan flags are `--config`, `--modules`, `--format`, `--output`, `--fail-on`, `--min-coverage`, `--concurrency`, `--timeout`, and `--force`. Scan supports `tls,http,dns` and terminal/JSON output; SARIF is rejected as unimplemented. Active configuration is rejected. `--no-color` is planned; use `NO_COLOR` today. `--profile quick/full`, `--with-intel`, `--active`, and `--authorize-active` are not supported aliases. Default scope is the exact target host, scheme and port; a supplied config defines explicit scope.
