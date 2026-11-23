# Architecture and boundaries

## Pipeline

```text
CLI / SDK / GitHub Action
          |
     config + policy validation
          |
 target normalization -> scope & egress policy
          |
        scheduler (DAG, context, budgets)
          |
  module probes -> observations + diagnostics
          |
    rule engine (versioned catalog)
          |
 findings + statuses -> scoring + coverage
          |
      report schema v1
          |
    terminal | JSON | SARIF
```

**Go owns** networking, collection, rule evaluation, score, coverage and canonical JSON. **TypeScript owns** process invocation, schema validation and CI integration only. The Go process must not depend on Node.

## Proposed production source layout

```text
cmd/wasp/main.go
internal/cli/{root,scan,modules,rules,config,report,version,completion}.go
internal/config/{load,validate,defaults}.go
internal/engine/{engine,plan,scheduler,budget,target,registry}.go
internal/network/{dialer,http,resolver,scope,rate_limit}.go
internal/modules/
  tls/{certificate,handshake}.go
  http/{response,headers,cookies,wellknown}.go
  dns/{records,dnssec}.go
  email/{spf,dkim,dmarc,mx}.go
  domain/{rdap}.go
  network/{asn,geo,ports,traceroute}.go
  discovery/{hosts}.go
internal/rules/{catalog,registry,evaluate}.go
internal/scoring/{scoring,coverage,policy}.go
internal/output/{terminal,json,sarif}.go
pkg/report/{report,observation,finding,status}.go
schemas/{report.v1.schema.json,config.v1.schema.json}
packages/{sdk,github-action}/
```

Prefer `internal/modules` over `internal/checks`: a module is not itself a finding, rule or check. Do not expose implementation as public Go API prematurely. `pkg/report` is the only deliberately stable public Go surface in v1.

## Primary interfaces (illustrative, not frozen code)

```go
type Probe interface {
    ID() string
    Collect(ctx context.Context, in Input) (Observations, []Diagnostic)
}

type Rule interface {
    ID() string
    Evaluate(ctx context.Context, data EvidenceView, policy Policy) Evaluation
}

type ModuleManifest struct {
    ID string
    ProbeIDs []string
    RuleIDs []string
    Dependencies []string
    Mode Mode // passive or active
}
```

Collector outputs should be typed wherever possible. Observations contain source, target endpoint, time, confidence, completeness and sanitized values. Raw wire artifacts are optional, bounded and excluded from default reports. Rule outcomes are statuses separate from finding records; the same evidence may support multiple rules without network duplication.

## Execution strategy

1. Canonicalize target and derive site/root domain/hostname/port. Never silently broaden to all subdomains.
2. Validate profile, target, module set and explicit authorization for every active probe.
3. Resolve and check all egress addresses; egress policy must apply to redirects, CNAMEs, IPv6 and connection reuse.
4. Plan probe DAG by dependencies. Group DNS queries and HTTP requests when safe.
5. Schedule bounded tasks; propagate context cancellation; enforce wall-clock and request budgets.
6. Store immutable observations and diagnostics; evaluation is pure and side-effect-free.
7. Evaluate rules once dependencies settle; map outcomes to findings and coverage.
8. Apply documented score policy and output writer. Serialize in stable order by module/probe/rule/resource.

## Extensibility

A module registers a manifest and typed probes; a rule catalog publishes independent stable rule IDs. Unknown module/rule IDs are fatal config validation errors. Version rules separately from engine binary for repeatability. Reports have a top-level `schema_version` and `policy_version`; downstream consumers should ignore unknown optional properties, but reject unsupported major schema revisions. Consider out-of-process plugins only after threat-modeling.

## Data boundaries

No storage or authentication in core CLI. A future service integration should invoke the binary or SDK, supply explicit target/scope/policy, and ingest versioned reports; asynchronous job coordination and history belong outside the engine. Never bake tenant-specific assumptions into the report or scanner.
