# Detect the root directory of this Makefile
# Explicitly strip the trailing slash from the path
# We will add the slash manually when required to prevent double slashes in the paths
PROJECT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

## Location to install dependencies to
# If you are setting this externally then you must use an absolute path
LOCALBIN ?= $(PROJECT_DIR)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

# YAMLLINT_VERSION defines the yamllint version to download from GitHub releases.
YAMLLINT_VERSION ?= 1.35.1

# YQ_VERSION defines the yq version to download from GitHub releases.
YQ_VERSION ?= v4.45.4

# Prefer binaries in the local bin directory over system binaries.
export PATH := $(abspath $(LOCALBIN)):$(PATH)
export CARGO_TERM_COLOR := always

# The 'all' target is the default goal.
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

.PHONY: konflux-filter-unused-redhat-repos
konflux-filter-unused-redhat-repos: sync-git-submodules ## Filter unused repositories from redhat.repo files in both runtime and build lock folders
	@echo "Filtering unused repositories from runtime lock folder..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/rpm-lock filter-unused-repos REPO_FILE=$(PROJECT_DIR)/.konflux/lock-runtime/redhat.repo
	@echo "Filtering unused repositories from build lock folder..."
	$(MAKE) -C $(PROJECT_DIR)/telco5g-konflux/scripts/rpm-lock filter-unused-repos REPO_FILE=$(PROJECT_DIR)/.konflux/lock-build/redhat.repo
	@echo "Filtering completed for both lock folders."

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
konflux-all: konflux-filter-unused-redhat-repos konflux-update-tekton-task-refs ## Run all Konflux-related targets
	@echo "All Konflux targets completed successfully."

# Rust build targets

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
rust-ci: rust-deps rust-fmt rust-check rust-clippy rust-test ## Run all Rust CI checks (used for Github actions workflow)
	@echo "All Rust CI checks completed successfully."

.PHONY: help
help: ## Display available targets
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
