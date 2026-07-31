BINARY  := gluetun-proton-updater
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= gluetun-proton-list-updater

GO_LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into ./bin
	go build -trimpath -ldflags="$(GO_LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

.PHONY: run
run: ## Run locally (expects PROTON_USERNAME/PROTON_PASSWORD in the environment)
	go run ./cmd/$(BINARY)

.PHONY: test
test: ## Run tests
	go test ./... -race -count=1

.PHONY: cover
cover: ## Run tests with a coverage summary
	go test ./... -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint if it is installed
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || \
		echo "golangci-lint not installed; skipping"

.PHONY: check
check: vet test ## Vet and test

.PHONY: tidy
tidy: ## Tidy go.mod
	go mod tidy

.PHONY: image
image: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin coverage.out

# --- Integration testing against a real Gluetun container --------------------
# These targets verify the control-server contract against Gluetun itself, which
# is the only way to catch a change in its behaviour. The WireGuard key is random
# on purpose: the tunnel never comes up, and none of these tests need it to.

GLUETUN_VERSION ?= v3.41.3
ITEST_CONTAINER := gluetun-itest
ITEST_PORT      ?= 18000
ITEST_APIKEY    ?= itest-secret
ITEST_COUNTRY   ?= Sweden

.PHONY: integration-up
integration-up: ## Start a throwaway Gluetun container for integration tests
	@docker rm -f $(ITEST_CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(ITEST_CONTAINER) \
		--cap-add=NET_ADMIN --device=/dev/net/tun \
		-p $(ITEST_PORT):8000 \
		-e VPN_SERVICE_PROVIDER=protonvpn \
		-e VPN_TYPE=wireguard \
		-e WIREGUARD_PRIVATE_KEY="$$(head -c 32 /dev/urandom | base64)" \
		-e SERVER_COUNTRIES=$(ITEST_COUNTRY) \
		-e HTTP_CONTROL_SERVER_ADDRESS=":8000" \
		-e HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"name":"itest","auth":"apikey","apikey":"$(ITEST_APIKEY)"}' \
		-e UPDATER_PERIOD=0 \
		-e PORT_FORWARD_ONLY=on \
		-e VPN_PORT_FORWARDING=on \
		-e HEALTH_VPN_DURATION_INITIAL=6h \
		-e HEALTH_RESTART_VPN=off \
		qmcgaw/gluetun:$(GLUETUN_VERSION)
	@echo "waiting for the control server..."
	@for i in $$(seq 1 30); do \
		curl -fsS -m 2 -H "X-API-Key: $(ITEST_APIKEY)" \
			http://127.0.0.1:$(ITEST_PORT)/v1/vpn/status >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; echo "gluetun did not become ready" >&2; exit 1

.PHONY: integration-down
integration-down: ## Remove the throwaway Gluetun container
	@docker rm -f $(ITEST_CONTAINER) >/dev/null 2>&1 || true

.PHONY: integration
integration: integration-up ## Run integration tests against a real Gluetun container
	# Gluetun has two storage layouts: current versions keep one file per provider
	# under /gluetun/servers/, older ones a single /gluetun/servers.json. Copy
	# whichever this Gluetun produced; the test handles both shapes.
	@docker cp $(ITEST_CONTAINER):/gluetun/servers/protonvpn.json \
		/tmp/$(ITEST_CONTAINER)-servers.json 2>/dev/null || \
	 docker cp $(ITEST_CONTAINER):/gluetun/servers.json \
		/tmp/$(ITEST_CONTAINER)-servers.json
	@GLUETUN_ITEST_URL=http://127.0.0.1:$(ITEST_PORT) \
	 GLUETUN_ITEST_API_KEY=$(ITEST_APIKEY) \
	 GLUETUN_ITEST_COUNTRY=$(ITEST_COUNTRY) \
	 GLUETUN_ITEST_SERVERS_FILE=/tmp/$(ITEST_CONTAINER)-servers.json \
	 go test -tags integration ./internal/gluetunapi/ -v -count=1 -timeout 10m; \
	 status=$$?; $(MAKE) integration-down; exit $$status
