GO ?= go
BIN ?= bin/wasp
.PHONY: fmt fmt-check lint test test-race build schema verify
fmt:
	gofmt -w cmd internal pkg
fmt-check:
	@test -z "$(shell gofmt -l cmd internal pkg)" || (gofmt -l cmd internal pkg; exit 1)
lint:
	$(GO) vet ./...
test:
	$(GO) test ./...
test-race:
	$(GO) test -race ./...
build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags "-X github.com/caseypc/wasp/internal/cli.Version=dev" -o $(BIN) ./cmd/wasp
schema:
	$(GO) test ./internal/config ./pkg/report
verify: fmt-check lint test test-race build