SHELL := /bin/bash

CARGO_MANIFEST := rust/Cargo.toml

TICKS ?= 1
DELTA ?= tick:0


.PHONY: help 

help:            ## Show this help
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test-serverd-bin: ## Run serverd tests that require the binary to be built
	cargo test -p serverd --features bin --manifest-path rust/Cargo.toml