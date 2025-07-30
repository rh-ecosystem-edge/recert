#!/usr/bin/env bash

if command -v apt >/dev/null 2>&1; then \
	sudo apt update && sudo apt install -y protobuf-compiler rustfmt; \
elif command -v yum >/dev/null 2>&1; then \
	sudo yum install -y protobuf-compiler rustfmt; \
elif command -v dnf >/dev/null 2>&1; then \
	sudo dnf install -y protobuf-compiler rustfmt ; \
elif command -v brew >/dev/null 2>&1; then \
	brew install protobuf rustfmt; \
else \
	echo "Warning: Could not detect package manager. Please install dependencies manually."; \
fi
