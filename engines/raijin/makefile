# Raijin Build System
# Enhanced Makefile for building and packaging Raijin

.DEFAULT_GOAL := help

# Detect OS and set appropriate flags
OSFLAG :=
BINARY_NAME := raijin
BUILD_DIR := build
SIGNATURES_DIR := $(BUILD_DIR)/signatures
CONFIG_DIR := $(BUILD_DIR)/config

ifeq ($(OS),Windows_NT)
	# Raijin can't be built on Windows!
	# For information on how to build Raijin for Windows see the workflow file in .github/workflows/build-linux-to-win.yml
	$(error Raijin cannot be built natively on Windows. Use cross-compilation from Linux.)
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		OSFLAG += --target x86_64-unknown-linux-musl
		BINARY_PATH := target/x86_64-unknown-linux-musl/release/$(BINARY_NAME)
	endif
	ifeq ($(UNAME_S),Darwin)
		BINARY_PATH := target/release/$(BINARY_NAME)
	endif
endif

.PHONY: help build clean package install-signatures

help: ## Show this help message
	@echo "Raijin Build System"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          - Build the release binary"
	@echo "  make package        - Create a complete build package"
	@echo "  make clean          - Clean build artifacts"

build: ## Build RAIJIN release version (both raijin and raijin-util)
	@echo "[!] The build has a bunch of dependencies"
	@echo "[i] For information on how to fulfill these prerequisites see the workflow file in .github/workflows/"
	@echo "[+] Building RAIJIN release version ..."
	@USE_MUSL=""; \
	if [ "$(OSFLAG)" != "" ]; then \
		if command -v rustup >/dev/null 2>&1; then \
			if rustup target list --installed 2>/dev/null | grep -q "x86_64-unknown-linux-musl"; then \
				USE_MUSL="$(OSFLAG)"; \
				echo "[+] Using musl target for static binary"; \
			else \
				echo "[!] musl target not installed. Installing..."; \
				if rustup target add x86_64-unknown-linux-musl 2>/dev/null; then \
					USE_MUSL="$(OSFLAG)"; \
					echo "[+] musl target installed successfully"; \
				else \
					echo "[!] Could not install musl target. Building without it..."; \
				fi; \
			fi; \
		else \
			echo "[!] rustup not found. Building without musl target (dynamic binary)"; \
		fi; \
	fi; \
	cargo build --release $$USE_MUSL --bin raijin --bin raijin-util || (echo "[!] Build with musl target failed, trying without target..." && cargo build --release --bin raijin --bin raijin-util)
	@if [ -f "$(BINARY_PATH)" ]; then \
		echo "[+] Build successful!"; \
		echo "[+] Binary location: $(BINARY_PATH)"; \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		echo "[+] Build successful!"; \
		echo "[+] Binary location: target/release/$(BINARY_NAME)"; \
		BINARY_PATH="target/release/$(BINARY_NAME)"; \
	else \
		echo "[!] Build failed or binary not found"; \
		exit 1; \
	fi
	@if [ -f "target/release/raijin-util" ] || [ -f "target/x86_64-unknown-linux-musl/release/raijin-util" ]; then \
		echo "[+] raijin-util binary built successfully"; \
	fi

package: build fetch-signatures install-signatures ## Create a complete build package with binary, signatures, config, and usage guide
	@echo "[+] Creating build package ..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(SIGNATURES_DIR)
	@mkdir -p $(CONFIG_DIR)
	@echo "[+] Copying binaries to $(BUILD_DIR)/ ..."
	@if [ -f "$(BINARY_PATH)" ]; then \
		cp $(BINARY_PATH) $(BUILD_DIR)/$(BINARY_NAME); \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		cp target/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME); \
	else \
		echo "[!] Binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@chmod +x $(BUILD_DIR)/$(BINARY_NAME)
	@if [ -f "target/release/raijin-util" ]; then \
		cp target/release/raijin-util $(BUILD_DIR)/raijin-util; \
		chmod +x $(BUILD_DIR)/raijin-util; \
	elif [ -f "target/x86_64-unknown-linux-musl/release/raijin-util" ]; then \
		cp target/x86_64-unknown-linux-musl/release/raijin-util $(BUILD_DIR)/raijin-util; \
		chmod +x $(BUILD_DIR)/raijin-util; \
	fi
	@echo "[+] Creating usage guide ..."
	@cp USAGE.md $(BUILD_DIR)/ 2>/dev/null || echo "[!] USAGE.md not found, creating from template..."
	@test -f $(BUILD_DIR)/USAGE.md || echo "# Raijin Usage Guide\n\nSee README.md for usage instructions." > $(BUILD_DIR)/USAGE.md
	@echo "[+] Creating config files ..."
	@test -f $(CONFIG_DIR)/excludes.cfg || printf '%s\n' \
		"# Raijin Exclusions Configuration" \
		"#" \
		"# Add regex patterns here to exclude paths from scanning." \
		"# One pattern per line. Lines starting with # are comments." \
		"#" \
		"# Examples:" \
		"#   ^/proc/.*          - Exclude everything under /proc" \
		"#   .*\\.log$$           - Exclude all .log files" \
		"#   .*node_modules.*   - Exclude node_modules directories" \
		"#" \
		"# See config/excludes.cfg.example for more examples." \
		> $(CONFIG_DIR)/excludes.cfg
	@echo "[+] Copying LICENSE ..."
	@cp LICENSE $(BUILD_DIR)/ 2>/dev/null || echo "[!] LICENSE not found"
	@echo ""
	@echo ""
	@echo "[✓] Build package created successfully!"
	@echo "[✓] Package location: $(BUILD_DIR)/"
	@echo "[✓] Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@if [ -f "$(BUILD_DIR)/raijin-util" ]; then \
		echo "[✓] Utility: $(BUILD_DIR)/raijin-util"; \
	fi
	@echo "[✓] Signatures: $(SIGNATURES_DIR)/"
	@echo "[✓] Config: $(CONFIG_DIR)/"
	@echo "[✓] Usage guide: $(BUILD_DIR)/USAGE.md"

fetch-signatures: ## Fetch YARA (YARA-Forge Core) and Sigma (SigmaHQ Core) signatures
	@echo "[+] Fetching YARA signatures from remote repositories ..."
	@mkdir -p ./signatures/yara
	@mkdir -p ./tmp
	@echo "[+] Downloading YARA rules from yara-forge ..."
	@find ./signatures/yara -type f \( -name "*.yar" -o -name "*.yara" \) -delete 2>/dev/null || true
	@if command -v wget >/dev/null 2>&1; then \
		wget -q https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip -O ./tmp/yara-forge-rules-core.zip && \
		unzip -q -o ./tmp/yara-forge-rules-core.zip -d ./tmp/yara-forge 2>/dev/null || true && \
		find ./tmp/yara-forge -name "*.yar" -exec cp {} ./signatures/yara/ \; 2>/dev/null || true; \
	elif command -v curl >/dev/null 2>&1; then \
		curl -sL https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip -o ./tmp/yara-forge-rules-core.zip && \
		unzip -q -o ./tmp/yara-forge-rules-core.zip -d ./tmp/yara-forge 2>/dev/null || true && \
		find ./tmp/yara-forge -name "*.yar" -exec cp {} ./signatures/yara/ \; 2>/dev/null || true; \
	else \
		echo "[!] Neither wget nor curl found. Skipping YARA rules download."; \
	fi
	@rm -rf ./tmp
	@echo "[+] YARA signatures fetched successfully"
	@echo "[+] Fetching Sigma signatures from SigmaHQ (Core) ..."
	@mkdir -p ./signatures/sigma
	@mkdir -p ./tmp
	@find ./signatures/sigma -type f \( -name "*.yml" -o -name "*.yaml" \) -delete 2>/dev/null || true
	@if command -v wget >/dev/null 2>&1; then \
		wget -q https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip -O ./tmp/sigma_core.zip && \
		unzip -q -o ./tmp/sigma_core.zip -d ./tmp/sigma-core 2>/dev/null || true && \
		find ./tmp/sigma-core -name "*.yml" -exec cp {} ./signatures/sigma/ \; 2>/dev/null || true; \
	elif command -v curl >/dev/null 2>&1; then \
		curl -sL https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip -o ./tmp/sigma_core.zip && \
		unzip -q -o ./tmp/sigma_core.zip -d ./tmp/sigma-core 2>/dev/null || true && \
		find ./tmp/sigma-core -name "*.yml" -exec cp {} ./signatures/sigma/ \; 2>/dev/null || true; \
	else \
		echo "[!] Neither wget nor curl found. Skipping Sigma rules download."; \
	fi
	@rm -rf ./tmp
	@echo "[+] Sigma signatures fetched successfully"

install-signatures: ## Install signatures (YARA from YARA-Forge, optional local IOCs) to build directory
	@echo "[+] Setting up signatures ..."
	@mkdir -p $(SIGNATURES_DIR)
	@if [ -d "./signatures" ]; then \
		echo "[+] Found local signatures directory, copying ..."; \
		cp -r ./signatures/* $(SIGNATURES_DIR)/ 2>/dev/null || true; \
	elif [ -L "./signatures" ]; then \
		echo "[+] Found signature symlink, following ..."; \
		cp -rL ./signatures/* $(SIGNATURES_DIR)/ 2>/dev/null || true; \
	else \
		echo "[!] No local signatures found. Run 'make fetch-signatures' to download them."; \
		echo "[+] Creating placeholder structure ..."; \
		mkdir -p $(SIGNATURES_DIR)/yara; \
		mkdir -p $(SIGNATURES_DIR)/sigma; \
		mkdir -p $(SIGNATURES_DIR)/iocs; \
		echo "# Place YARA rules (.yar files) in this directory" > $(SIGNATURES_DIR)/yara/README.txt; \
		echo "# Place Sigma rules (.yml files) in this directory" > $(SIGNATURES_DIR)/sigma/README.txt; \
		echo "# Place optional custom IOC files in this directory" > $(SIGNATURES_DIR)/iocs/README.txt; \
	fi
	@mkdir -p $(SIGNATURES_DIR)/iocs
	@test -f $(SIGNATURES_DIR)/iocs/hash-iocs.txt || echo "# Optional custom hash IOCs" > $(SIGNATURES_DIR)/iocs/hash-iocs.txt
	@test -f $(SIGNATURES_DIR)/iocs/filename-iocs.txt || echo "# Optional custom filename IOCs" > $(SIGNATURES_DIR)/iocs/filename-iocs.txt
	@test -f $(SIGNATURES_DIR)/iocs/c2-iocs.txt || echo "# Optional custom C2 IOCs" > $(SIGNATURES_DIR)/iocs/c2-iocs.txt
	@test -f $(SIGNATURES_DIR)/iocs/keywords.txt || echo "# Optional custom keyword IOCs" > $(SIGNATURES_DIR)/iocs/keywords.txt
	@echo "[+] Signatures setup complete"

dist: build fetch-signatures ## Create distribution package (downloads signatures from GitHub)
	@echo "[+] Creating distribution package ..."
	@mkdir -p ./dist/raijin/signatures
	@mkdir -p ./tmp
	@echo "[+] Copying binaries ..."
	@if [ -f "$(BINARY_PATH)" ]; then \
		cp $(BINARY_PATH) ./dist/raijin/$(BINARY_NAME); \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		cp target/release/$(BINARY_NAME) ./dist/raijin/$(BINARY_NAME); \
	else \
		echo "[!] Binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@chmod +x ./dist/raijin/$(BINARY_NAME)
	@if [ -f "target/release/raijin-util" ]; then \
		cp target/release/raijin-util ./dist/raijin/raijin-util; \
		chmod +x ./dist/raijin/raijin-util; \
		echo "[+] Copied raijin-util binary"; \
	fi
	@echo "[+] Copying signatures to ./dist/raijin/signatures ..."
	@cp -r ./signatures/yara ./dist/raijin/signatures/ 2>/dev/null || true
	@mkdir -p ./dist/raijin/signatures/iocs
	@test -f ./dist/raijin/signatures/iocs/hash-iocs.txt || echo "# Optional custom hash IOCs" > ./dist/raijin/signatures/iocs/hash-iocs.txt
	@test -f ./dist/raijin/signatures/iocs/filename-iocs.txt || echo "# Optional custom filename IOCs" > ./dist/raijin/signatures/iocs/filename-iocs.txt
	@test -f ./dist/raijin/signatures/iocs/c2-iocs.txt || echo "# Optional custom C2 IOCs" > ./dist/raijin/signatures/iocs/c2-iocs.txt
	@test -f ./dist/raijin/signatures/iocs/keywords.txt || echo "# Optional custom keyword IOCs" > ./dist/raijin/signatures/iocs/keywords.txt
	@echo "[+] Copying documentation ..."
	@cp LICENSE ./dist/raijin/ 2>/dev/null || true
	@cp README.md ./dist/raijin/ 2>/dev/null || true
	@test -f USAGE.md && cp USAGE.md ./dist/raijin/ || true
	@echo "[+] Creating config directory ..."
	@mkdir -p ./dist/raijin/config
	@printf '%s\n' \
		"# Raijin Exclusions Configuration" \
		"#" \
		"# Add regex patterns here to exclude paths from scanning." \
		"# One pattern per line. Lines starting with # are comments." \
		"#" \
		"# Examples:" \
		"#   ^/proc/.*          - Exclude everything under /proc" \
		"#   .*\\.log$$           - Exclude all .log files" \
		"#   .*node_modules.*   - Exclude node_modules directories" \
		"#" \
		"# See config/excludes.cfg.example for more examples." \
		> ./dist/raijin/config/excludes.cfg
	@rm -rf ./tmp
	@echo "[✓] Distribution package created in ./dist/raijin/"

clean: ## Clean build artifacts
	@echo "[+] Cleaning up ..."
	@rm -rf ./target
	@rm -rf ./dist
	@rm -rf ./tmp
	@rm -rf $(BUILD_DIR)
	@echo "[+] Clean complete"

clean-build: ## Clean only the build directory (keep target/)
	@echo "[+] Cleaning build directory ..."
	@rm -rf $(BUILD_DIR)
	@echo "[+] Build directory cleaned"
