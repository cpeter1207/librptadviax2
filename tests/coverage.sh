#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

# Keep the established compiler/debug coverage profile and include real public
# C callers. show-env/report is cargo-llvm-cov's external-test workflow.
export RUSTUP_TOOLCHAIN=nightly-2025-02-20
coverage_cargo=${CARGO:-cargo}
mkdir -p build/coverage
"$coverage_cargo" llvm-cov show-env --branch --export-prefix > build/coverage/env.sh
. ./build/coverage/env.sh
"$coverage_cargo" llvm-cov clean --workspace
"$coverage_cargo" build --locked

coverage_dir=$(pwd)/build/coverage/ffi
mkdir -p "$coverage_dir"
cp "$CARGO_LLVM_COV_TARGET_DIR/debug/librptadviax2.so" "$coverage_dir/librptadviax2.so.2"
ln -sf librptadviax2.so.2 "$coverage_dir/librptadviax2.so"
# SONAME lookup must select this measured DSO even with another build present.
export LD_LIBRARY_PATH=$coverage_dir:${LD_LIBRARY_PATH-}

# Native codec fixtures use this scratch directory independently of Cargo's
# selected target. All source/profile objects still use the same instrumented build.
mkdir -p target
"$coverage_cargo" test --all-targets --locked
make coverage-ffi-check
"$coverage_cargo" llvm-cov report --branch --json --output-path build/coverage/rust.json
python3 tests/check_coverage.py build/coverage/rust.json
