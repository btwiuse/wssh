#!/usr/bin/env bash
#
# Builds the browser SSH client to WebAssembly and drops it, together with the
# matching wasm_exec.js runtime, next to the front end that loads it.
#
# The binary is not committed: it is a build artefact of client/main.go, and
# wasm_exec.js has to come from the same Go release that produced it.
#
set -euo pipefail

readonly HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly OUT="$HERE/../cmd/wssh/static"

mkdir -p "$OUT"

# CGO_ENABLED=0 is required on hosts (Termux, certain Linux distributions)
# that default it on: cgo is unavailable for js/wasm, and leaving the flag on
# makes os/user skip the build tag that provides its js/wasm backend. The
# upstream Go toolchain leaves cgo off everywhere it is not supported, so this
# only matters for the cross-compile step.
echo "building client -> $OUT/ssh.wasm"
(
	cd "$HERE"
	CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -o "$OUT/ssh.wasm" ./cmd/webssh-web
)

# wasm_exec.js must match the Go toolchain that built the binary, or the two
# disagree about the runtime ABI and fail in confusing ways.
cp -- "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT/wasm_exec.js"

echo "done:"
ls -lh "$OUT/ssh.wasm" "$OUT/wasm_exec.js"
