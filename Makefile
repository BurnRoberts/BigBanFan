BINARY     = bigbanfan
BIN_DIR    = bin
BUILD_DIR  = $(BIN_DIR)
INSTALL    = /usr/local/bin/$(BINARY)
SERVICE    = bigbanfan.service
SYSTEMD_DIR = /etc/systemd/system
CONFIG_DIR  = /etc/bigbanfan
DB_DIR      = /var/lib/bigbanfan
LOG_DIR     = /var/log

# ── Version ───────────────────────────────────────────────────
# Bump this to tag a new release. Injected into the binary via ldflags.
# Check deployed version: bigbanfan -version
VERSION    = 0.1.3

GO         = go
LDFLAGS    = -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: all build clean install uninstall gen-certs deps vet test

all: deps build

## deps: Download and tidy Go module dependencies
deps:
	$(GO) mod tidy

## build: Compile the BigBanFan binary
build: deps
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## vet: Run go vet static analysis
vet:
	$(GO) vet ./...

## test: Run all unit tests
test:
	$(GO) test -v ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

## install: Install binary + config + systemd unit + certs (requires root)
install: build
	install -Dm755 $(BUILD_DIR)/$(BINARY) $(INSTALL)
	install -d $(CONFIG_DIR) $(DB_DIR) $(LOG_DIR)
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		install -m 640 config.example.yaml $(CONFIG_DIR)/config.yaml; \
		echo "Installed default config to $(CONFIG_DIR)/config.yaml — edit before starting!"; \
	fi
	@if [ -f certs/node.crt ] && [ -f certs/node.key ]; then \
		install -m 644 certs/node.crt $(CONFIG_DIR)/node.crt; \
		install -m 600 certs/node.key $(CONFIG_DIR)/node.key; \
		echo "Installed TLS certs to $(CONFIG_DIR)/"; \
	else \
		echo "WARNING: certs/node.crt or certs/node.key not found — run 'make gen-certs' first"; \
	fi
	install -m 644 $(SERVICE) $(SYSTEMD_DIR)/$(SERVICE)
	systemctl daemon-reload
	@echo "Run: systemctl enable --now bigbanfan"

## uninstall: Remove binary and systemd unit (does NOT delete config or DB)
uninstall:
	systemctl stop bigbanfan 2>/dev/null || true
	systemctl disable bigbanfan 2>/dev/null || true
	rm -f $(INSTALL) $(SYSTEMD_DIR)/$(SERVICE)
	systemctl daemon-reload
	@echo "Uninstalled. Config and database preserved at $(CONFIG_DIR) and $(DB_DIR)"

## gen-certs: Generate self-signed TLS cert + key for development/testing
gen-certs:
	@mkdir -p certs
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-keyout certs/node.key -out certs/node.crt \
		-days 3650 -nodes \
		-subj "/CN=bigbanfan"
	@echo "Generated: certs/node.crt  certs/node.key"
	@echo "Run 'make install' to copy them to $(CONFIG_DIR)/"

## gen-keys: Print two random 32-byte hex keys (node_key and client_key)
gen-keys:
	@echo "node_key:   $$(openssl rand -hex 32)"
	@echo "client_key: $$(openssl rand -hex 32)"
