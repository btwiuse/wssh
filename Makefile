# Build entry point.
#
# Bare `make` lists the targets. `make wssh` builds a working wssh, and that
# dependency matters more than the wording suggests: cmd/wssh embeds the whole
# static/ directory, so a binary built while ssh.wasm is missing compiles fine,
# runs fine, and serves a page whose worker dies on a 404. Keeping the wasm a
# prerequisite of the build is what turns that silent breakage into a build
# that either produces it or fails.
#
# Note for scripts and CI: the default goal prints help and exits 0 having
# built nothing. Name the target.

.DEFAULT_GOAL := help

GO     ?= go
BIN    ?= bin
STATIC := cmd/wssh/static
WASM   := $(STATIC)/ssh.wasm
WASMJS := $(STATIC)/wasm_exec.js

# Everything that can change the browser client. Listed explicitly rather than
# found at parse time so the dependency is visible and stays correct when files
# move.
WASM_SRC := client/build.sh client/client.go client/wasm.go client/wasmauth.go \
            client/cmd/webssh-web/main.go go.mod

.PHONY: wssh
wssh: $(WASM) $(WASMJS) ## build bin/wssh, populating static/ first
	@mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/wssh ./cmd/wssh
	@echo "built $(BIN)/wssh"

# build.sh emits both files in one pass, because wasm_exec.js has to come from
# the same Go release that produced ssh.wasm or the two disagree about the
# runtime ABI. GNU Make 3.81 (still the macOS default) has no grouped targets,
# so the second file takes the first as its prerequisite instead.
$(WASM): $(WASM_SRC)
	@./client/build.sh

$(WASMJS): $(WASM)
	@test -f $@ || ./client/build.sh

.PHONY: generate
generate: ## run every //go:generate directive, which populates static/
	$(GO) generate ./...

.PHONY: install
install: ## install wssh into GOBIN
	$(GO) install ./cmd/wssh

.PHONY: serve
serve: wssh ## build, then run the server with the browser front end
	$(BIN)/wssh web

.PHONY: test
test: ## run the test suite
	$(GO) test ./...

.PHONY: vet
vet: ## run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## format the tree in place
	gofmt -w .

.PHONY: check
check: vet test ## vet and test, the gate before committing

.PHONY: clean
clean: ## remove build output, including the browser client
	rm -rf $(BIN) $(WASM) $(WASMJS)

.PHONY: help
help: ## print this list
	@echo "wssh - SSH over WebSocket, with a browser front end"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
	@echo
	@echo "Run 'make <target>' to build one."
