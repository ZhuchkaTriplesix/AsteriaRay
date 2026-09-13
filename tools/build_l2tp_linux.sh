#!/usr/bin/env bash
# Build asteriaray-l2tp for Linux and install it into linux/asteriaray-l2tp so CMake bundles it next to the app.
# Usage: from repo root: ./tools/build_l2tp_linux.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="${ROOT}/tools/asteriaray-l2tp"
OUT="${ROOT}/linux/asteriaray-l2tp"

echo "Building asteriaray-l2tp in ${CRATE_DIR}..."
cargo build --release --manifest-path "${CRATE_DIR}/Cargo.toml"

BIN="${CRATE_DIR}/target/release/asteriaray-l2tp"
if [[ -f "${BIN}" ]]; then
    cp -f "${BIN}" "${OUT}"
    chmod +x "${OUT}"
    echo "Installed: ${OUT}"
    "${OUT}" --version
else
    echo "Build failed: binary ${BIN} not found" >&2
    exit 1
fi
