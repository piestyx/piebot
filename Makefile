SHELL := /bin/bash

CARGO_MANIFEST := rust/Cargo.toml

TICKS ?= 1
DELTA ?= tick:0


.PHONY: help 

help:            ## Show this help
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
