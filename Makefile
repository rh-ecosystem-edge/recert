# Detect the root directory of this Makefile
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: konflux-filter-unused-redhat-repos
konflux-filter-unused-redhat-repos: ## Filter unused repositories from redhat.repo files in both runtime and build lock folders
	@echo "Filtering unused repositories from runtime lock folder..."
	$(MAKE) -C $(ROOT_DIR)telco5g-konflux/scripts/rpm-lock filter-unused-repos REPO_FILE=$(ROOT_DIR).konflux/lock-runtime/redhat.repo
	@echo "Filtering unused repositories from build lock folder..."
	$(MAKE) -C $(ROOT_DIR)telco5g-konflux/scripts/rpm-lock filter-unused-repos REPO_FILE=$(ROOT_DIR).konflux/lock-build/redhat.repo
	@echo "Filtering completed for both lock folders."

.PHONY: konflux-update-tekton-task-refs
konflux-update-tekton-task-refs: ## Update task references in Tekton pipeline files
	@echo "Updating task references in Tekton pipeline files..."
	$(MAKE) -C $(ROOT_DIR)telco5g-konflux/scripts/tekton update-task-refs PIPELINE_FILES="$(shell find $(ROOT_DIR).tekton -name '*.yaml' -not -name 'OWNERS' | tr '\n' ' ')"
	@echo "Task references updated successfully."

.PHONY: konflux-all
konflux-all: konflux-filter-unused-redhat-repos konflux-update-tekton-task-refs ## Run all Konflux-related targets
	@echo "All Konflux targets completed successfully."

.PHONY: help
help: ## Display available targets
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
