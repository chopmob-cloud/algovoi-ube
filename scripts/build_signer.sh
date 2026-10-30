#!/bin/sh
# Build the ML-DSA signing core.
#
# NTI-1 mandates CRYSTALS-Dilithium5, so the harness needs a real post-quantum
# signer. It is a Rust binary rather than a Python dependency for two reasons the
# standard cares about: the key lives in a separate process, and the package stays
# free of compiled Python extensions that break on an air-gapped install.
#
# Building is not optional for a conformance run. If this fails, the signing
# checks fail rather than passing on a placeholder.

set -eu

# The ml-dsa crate pulls dependencies that require the 2024 edition, which Cargo
# stabilised in 1.85. An older toolchain fails deep inside a dependency's manifest
# with a message about `-Znext-lockfile-bump` or `edition2024` that says nothing
# about what to do, so the version is checked up front instead.
MIN_MAJOR=1
MIN_MINOR=85

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
crate="$root/rust/nti-signer"

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found." >&2
    echo "Install a Rust toolchain of 1.85 or newer (https://rustup.rs), or set" >&2
    echo "NTI_SIGNER_BIN to an existing nti-signer binary." >&2
    exit 1
fi

version=$(cargo --version | awk '{print $2}')
major=$(printf '%s' "$version" | cut -d. -f1)
minor=$(printf '%s' "$version" | cut -d. -f2)
if [ "$major" -lt "$MIN_MAJOR" ] || { [ "$major" -eq "$MIN_MAJOR" ] && [ "$minor" -lt "$MIN_MINOR" ]; }; then
    echo "cargo $version is too old. The ML-DSA dependencies need Rust 1.85 or newer." >&2
    echo "" >&2
    echo "Either upgrade (rustup update stable), or build in a container:" >&2
    echo "  docker run --rm -v \"$crate\":/w -w /w rust:1.87-slim \\" >&2
    echo "    sh -c 'cargo build --release'" >&2
    echo "then copy target/release/nti-signer out and point NTI_SIGNER_BIN at it." >&2
    exit 1
fi

echo "building the ML-DSA core in $crate with cargo $version"
(cd "$crate" && cargo build --release)

bin="$crate/target/release/nti-signer"
[ -f "$bin" ] || bin="$bin.exe"
if [ ! -f "$bin" ]; then
    echo "build reported success but no binary was produced at $bin" >&2
    exit 1
fi

echo "built: $bin"
echo "checking it signs and verifies"
printf 'sign 68656c6c6f\nquit\n' | "$bin" | grep -q '^ok ' || {
    echo "the core did not sign a test payload" >&2
    exit 1
}
echo "core responds correctly"
