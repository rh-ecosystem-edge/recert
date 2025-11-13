# Detect the root directory of this Makefile
# Explicitly strip the trailing slash from the path
# We will add the slash manually when required to prevent double slashes in the paths
PROJECT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

## Location to install dependencies to
# If you are setting this externally then you must use an absolute path
LOCALBIN ?= $(PROJECT_DIR)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

# RHEL9_ACTIVATION_KEY defines the activation key to use for the rpm lock file for the runtime
# This should be set in your environment prior to running the `konflux-update-rpm-lock-runtime` target
RHEL9_ACTIVATION_KEY ?= ""

# RHEL9_ORG_ID defines the organization to use for the rpm lock file for the runtime
# This should be set in your environment prior to running the `konflux-update-rpm-lock-runtime` target
RHEL9_ORG_ID ?= ""

# The registry auth file is mounted into the container to allow for private registry pulls.
# This is automatically detected and mounted into the container if it exists on the host.
# If it does not exist, a warning is printed and the registry pulls may fail if not public.
# This can be set from the command line if the default is not correct for your environment.
REGISTRY_AUTH_FILE ?= $(shell echo $${XDG_RUNTIME_DIR:-/run/user/$$(id -u)})/containers/auth.json

# RHEL9_RELEASE defines the RHEL9 release version to update the rpm lock file for the runtime
# This is automatically extracted from the Containerfile
RHEL9_RELEASE ?= $(shell awk -F'[=:@]' '/^BUILDER_IMAGE=registry\.redhat\.io\/rhel9.*-els\/rhel:/ {print $$3}' $(PROJECT_DIR)/.konflux/container_build_args.conf)

# YAMLLINT_VERSION defines the yamllint version to download from GitHub releases.
YAMLLINT_VERSION ?= 1.35.1

# YQ_VERSION defines the yq version to download from GitHub releases.
YQ_VERSION ?= v4.45.4

# Prefer binaries in the local bin directory over system binaries.
export PATH := $(abspath $(LOCALBIN)):$(PATH)
export CARGO_TERM_COLOR := always

# The 'all' target is the default goal.
.DEFAULT_GOAL := all
.PHONY: all
all: yamllint rust-ci
	@echo "All linting and testing tasks completed successfully."

.PHONY: clean
clean:
	@rm -rf target
	@rm -rf $(LOCALBIN)

.PHONY: test
test: rust-test
	@echo "All testing tasks completed successfully."

# Konflux targets

.PHONY: sync-git-submodules
sync-git-submodules: ## Sync git submodules (honors SKIP_SUBMODULE_SYNC=yes)
	@echo "Checking git submodules"
	@if [ "$(SKIP_SUBMODULE_SYNC)" != "yes" ]; then \
		echo "Syncing git submodules"; \
		git submodule sync --recursive; \
		git submodule update --init --recursive; \
	else \
		echo "Skipping submodule sync"; \
	fi

.PHONY: konflux-update-rpm-lock-runtime
konflux-update-rpm-lock-runtime: sync-git-submodules ## Update the rpm lock file for the runtime
	@echo "Creating lock-runtime/tmp/ directory..."
	mkdir -p $(PROJECT_DIR)/.konflux/lock-runtime/tmp/
	@echo "Copying rpms.runtime.in.yaml to lock-runtime/tmp/ directory..."
	cp $(PROJECT_DIR)/.konflux/lock-runtime/rpms.in.yaml $(PROJECT_DIR)/.konflux/lock-runtime/tmp/rpms.in.yaml
	@cat $(PROJECT_DIR)/.konflux/lock-runtime/tmp/rpms.in.yaml
	@echo "Updating rpm lock file for the runtime..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/rpm-lock generate-rhel9-locks \
		LOCK_SCRIPT_TARGET_DIR=$(PROJECT_DIR)/.konflux/lock-runtime/tmp/ \
		RHEL9_EXECUTION_IMAGE=$$(awk -F'=' '/^RUNTIME_IMAGE=/ {print $$2}' $(PROJECT_DIR)/.konflux/container_build_args.conf | sed 's|ubi-minimal|ubi|g' | sed 's|@.*||') \
		RHEL9_IMAGE_TO_LOCK=$$(awk -F'=' '/^RUNTIME_IMAGE=/ {print $$2}' $(PROJECT_DIR)/.konflux/container_build_args.conf)
	@echo "Update rpms.lock.yaml with new contents..."
	cp $(PROJECT_DIR)/.konflux/lock-runtime/tmp/rpms.lock.yaml $(PROJECT_DIR)/.konflux/lock-runtime/rpms.lock.yaml
	# intentionally keep lock-runtime/tmp/ directory for debugging purposes
	@echo "RPM lock file updated successfully."

.PHONY: konflux-update-rpm-lock-build
konflux-update-rpm-lock-build: sync-git-submodules ## Update the rpm lock file for the build
	@echo "Creating lock-build/tmp/ directory..."
	mkdir -p $(PROJECT_DIR)/.konflux/lock-build/tmp/
	@echo "Copying rpms.build.in.yaml to lock-build/tmp/ directory..."
	cp $(PROJECT_DIR)/.konflux/lock-build/rpms.in.yaml $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml
	@echo "Replacing SSL_CLIENT_KEY and SSL_CLIENT_CERT in lock-build/tmp/rpms.in.yaml..."
	if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' 's|sslclientkey: $$SSL_CLIENT_KEY|sslclientkey: /etc/pki/entitlement/placeholder-key.pem|g' $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml; \
		sed -i '' 's|sslclientcert: $$SSL_CLIENT_CERT|sslclientcert: /etc/pki/entitlement/placeholder.pem|g' $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml; \
	else \
		sed -i 's|sslclientkey: $$SSL_CLIENT_KEY|sslclientkey: /etc/pki/entitlement/placeholder-key.pem|g' $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml; \
		sed -i 's|sslclientcert: $$SSL_CLIENT_CERT|sslclientcert: /etc/pki/entitlement/placeholder.pem|g' $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml; \
	fi
	@cat $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.in.yaml
	@echo "Updating rpm lock file for the build..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/rpm-lock generate-rhel9-locks \
		LOCK_SCRIPT_TARGET_DIR=$(PROJECT_DIR)/.konflux/lock-build/tmp/ \
		RHEL9_EXECUTION_IMAGE=$$(awk -F'=' '/^BUILDER_IMAGE=/ {print $$2}' $(PROJECT_DIR)/.konflux/container_build_args.conf | sed 's|@.*||') \
		RHEL9_IMAGE_TO_LOCK=$$(awk -F'=' '/^BUILDER_IMAGE=/ {print $$2}' $(PROJECT_DIR)/.konflux/container_build_args.conf) \
		RHEL9_RELEASE=$(RHEL9_RELEASE) \
		RHEL9_ACTIVATION_KEY=$(RHEL9_ACTIVATION_KEY) \
		RHEL9_ORG_ID=$(RHEL9_ORG_ID) \
		REGISTRY_AUTH_FILE=$(REGISTRY_AUTH_FILE) \
		;
	@echo "Update rpms.lock.yaml with new contents..."
	cp $(PROJECT_DIR)/.konflux/lock-build/tmp/rpms.lock.yaml $(PROJECT_DIR)/.konflux/lock-build/rpms.lock.yaml
	# intentionally keep lock-build/tmp/ directory for debugging purposes
	@echo "RPM lock file updated successfully."

.PHONY: konflux-update-tekton-task-refs
konflux-update-tekton-task-refs: sync-git-submodules ## Update task references in Tekton pipeline files
	@echo "Updating task references in Tekton pipeline files..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/tekton update-task-refs \
		PIPELINE_FILES="$$(find $(PROJECT_DIR)/.tekton -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 | xargs -0 -r printf '%s ')"
	@echo "Task references updated successfully."

.PHONY: yamllint-download
yamllint-download: sync-git-submodules $(LOCALBIN) ## Download yamllint
	@echo "Downloading yamllint..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/download \
		download-yamllint \
		DOWNLOAD_INSTALL_DIR=$(LOCALBIN) \
		DOWNLOAD_YAMLLINT_VERSION=$(YAMLLINT_VERSION)
	@echo "Yamllint downloaded successfully."

.PHONY: yamllint
yamllint: yamllint-download ## Lint YAML files in the repository
	@echo "Running yamllint on repository YAML files..."
	yamllint -c $(PROJECT_DIR)/.yamllint.yaml .
	@echo "YAML linting completed successfully."

.PHONY: yq
yq: sync-git-submodules $(LOCALBIN) ## Download yq
	@echo "Downloading yq..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/download \
		download-yq \
		DOWNLOAD_INSTALL_DIR=$(LOCALBIN) \
		DOWNLOAD_YQ_VERSION=$(YQ_VERSION)
	@echo "Yq downloaded successfully."

.PHONY: yq-sort-and-format
yq-sort-and-format: yq ## Sort keys/reformat all YAML files in the repository
	@echo "Sorting keys and reformatting YAML files..."
	@find . -name "*.yaml" -o -name "*.yml" | grep -v -E "(telco5g-konflux/|target/|vendor/|bin/|\.git/)" | while read file; do \
		echo "Processing $$file..."; \
		yq -i '.. |= sort_keys(.)' "$$file"; \
	done
	@echo "YAML sorting and formatting completed successfully."

.PHONY: konflux-all
konflux-all: konflux-update-rpm-lock-runtime konflux-update-rpm-lock-build konflux-update-tekton-task-refs ## Run all Konflux-related targets
	@echo "All Konflux targets completed successfully."

# Rust build targets

.PHONY: rust-compile
rust-compile: sync-git-submodules rust-deps ## Compile the Rust code
	@echo "Compiling Rust code..."
	cargo build --release --bin recert
	@echo "Compilation completed successfully."

.PHONY: rust-deps
rust-deps: ## Install Rust build dependencies (protobuf-compiler, rustfmt, rust, clippy)
	@echo "Installing Rust build dependencies..."
	$(PROJECT_DIR)/hack/rust-deps.sh
	@echo "Dependencies installed successfully."

.PHONY: rust-fmt
rust-fmt: ## Check Rust code formatting
	@echo "Checking Rust code formatting..."
	cargo fmt --check
	@echo "Formatting check completed successfully."

.PHONY: rust-check
rust-check: ## Check Rust code compilation
	@echo "Checking Rust code compilation..."
	cargo check
	@echo "Compilation check completed successfully."

.PHONY: rust-clippy
rust-clippy: ## Run Rust linter (clippy)
	@echo "Running Rust linter (clippy)..."
	cargo clippy
	@echo "Clippy check completed successfully."

.PHONY: rust-test
rust-test: ## Run Rust tests
	@echo "Running Rust tests..."
	cargo test
	@echo "Tests completed successfully."

.PHONY: rust-ci
rust-ci: rust-deps rust-fmt rust-check rust-clippy rust-test rust-compile ## Run all Rust CI checks (used for Github actions workflow)
	@echo "All Rust CI checks completed successfully."

.PHONY: help
help: ## Display available targets
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
