# gatewaydns-desktop — the GatewayDNS desktop application.
BIN     := gatewaydns-desktop
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X github.com/daboss2003/dns-desktop/internal/build.version=$(VERSION) \
  -X github.com/daboss2003/dns-desktop/internal/build.commit=$(COMMIT) \
  -X github.com/daboss2003/dns-desktop/internal/build.date=$(DATE)

.DEFAULT_GOAL := help
.PHONY: help build build-headless run test test-race fuzz vet fmt fmt-check lint tidy release-check clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the desktop application for this platform
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/gatewaydns-desktop

build-headless: ## Build a static binary with no window, for a server or a Pi
	CGO_ENABLED=0 go build -trimpath -tags nogui -ldflags '$(LDFLAGS)' -o $(BIN)-headless ./cmd/gatewaydns-desktop

run: build ## Build and run the desktop application
	./$(BIN)

test: ## Run the tests
	go test ./...

test-race: ## Run the tests under the race detector
	go test -race ./...

fuzz: ## Fuzz the wire codecs for a minute each
	go test -run=XXX -fuzz=FuzzUnpack -fuzztime=60s ./internal/dhcp/

vet: ## Run go vet
	go vet ./...

fmt: ## Format the tree
	gofmt -s -w .

fmt-check: ## Fail if any file is not gofmt clean
	@out=$$(gofmt -s -l .); if [ -n "$$out" ]; then echo "not gofmt clean:"; echo "$$out"; exit 1; fi

lint: ## Run golangci-lint
	golangci-lint run

tidy: ## Tidy the module
	go mod tidy

release-check: ## Fail if go.mod still carries a development replace directive
	@if grep -qE '^[[:space:]]*replace' go.mod; then \
	  echo "go.mod contains a replace directive; it must be removed before release:"; \
	  grep -nE '^[[:space:]]*replace' go.mod; exit 1; \
	fi
	@echo "go.mod is release-clean"

clean: ## Remove build artefacts
	rm -rf $(BIN) $(BIN)-headless coverage.out dist
