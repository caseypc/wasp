# Contributing

Thanks for helping improve WASP. The project is pre-1.0 and its interfaces may evolve; for substantial changes, open an issue before investing in a large pull request.

## Development setup

Use Go 1.25.0 or newer. The project has no Node.js or pnpm requirements.

```bash
go test ./...
go test -race ./...
go vet ./...
make fmt-check
```

Before opening a pull request, run `make verify`. It checks formatting, vet, tests, race tests, and a build without changing source files.

## Change expectations

- Keep network access bounded, scoped, and passive by default. Never test against systems without authorization.
- Add offline unit or fixture tests for behavior changes; normal tests must not depend on public services.
- Update the relevant documentation and schemas when a public contract changes.
- Keep module capability claims aligned with what the CLI actually implements. Planned catalog entries must not be presented as working features.
- Preserve stable rule identifiers and report compatibility, or document a deliberate migration.
- Do not include credentials, private target lists, or sensitive scan artifacts in issues or pull requests.

Pull requests should describe the behavior change, its safety implications, and the commands used to validate it. All contributions are subject to the Apache License 2.0.
