#!/usr/bin/env bash
# Select an already installed CI-compatible toolchain without installing anything.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "Usage: bash scripts/verify-host.sh prepare|cargo <arguments...>" >&2
    exit 2
fi

USER_HOME="$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
export RUSTUP_HOME="${SHOES_VERIFY_RUSTUP_HOME:-$USER_HOME/.rustup}"
export RUSTUP_TOOLCHAIN="${SHOES_VERIFY_TOOLCHAIN:-1.94.1}"
export RUSTUP_NO_UPDATE_CHECK=1
if [ ! -d "$RUSTUP_HOME" ]; then
    echo "Missing installed rustup home: $RUSTUP_HOME; provision the declared Rust toolchain first." >&2
    exit 1
fi
TOOLCHAIN_CARGO="$(rustup which --toolchain "$RUSTUP_TOOLCHAIN" cargo)"
TOOLCHAIN_BIN="$(dirname "$TOOLCHAIN_CARGO")"
export PATH="$TOOLCHAIN_BIN:$PATH"
export RUSTC="$TOOLCHAIN_BIN/rustc"
export RUSTDOC="$TOOLCHAIN_BIN/rustdoc"
export CARGO_HOME="${SHOES_VERIFY_CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${SHOES_VERIFY_TARGET_DIR:-target}"
export RUST_BACKTRACE=1
export CARGO_TERM_COLOR=always
export SHOES_TLS_PRIVACY_CAPTURE_DIR="${SHOES_TLS_PRIVACY_CAPTURE_DIR:-$HOME/shoes-tls-privacy-captures}"

case "$1" in
    prepare)
        [ "$#" -eq 1 ] || exit 2
        for TOOL in cc cmake perl; do
            command -v "$TOOL" >/dev/null || {
                echo "Missing native build prerequisite: $TOOL" >&2
                exit 1
            }
        done
        for TOOL in cargo rustc rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do
            if [ ! -x "$TOOLCHAIN_BIN/$TOOL" ]; then
                echo "Missing Rust component: $TOOLCHAIN_BIN/$TOOL; provision rustfmt/clippy first." >&2
                exit 1
            fi
        done
        "$TOOLCHAIN_CARGO" --version
        "$RUSTC" --version
        "$TOOLCHAIN_BIN/rustfmt" --version
        "$TOOLCHAIN_CARGO" clippy --version
        printf 'Toolchain: %s\nCargo cache: %s\nBuild target: %s\nComplete TLS captures: %s\n' \
            "$TOOLCHAIN_BIN" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$SHOES_TLS_PRIVACY_CAPTURE_DIR"
        ;;
    cargo)
        shift
        exec "$TOOLCHAIN_CARGO" "$@"
        ;;
    *)
        echo "Unsupported verification command: $1" >&2
        exit 2
        ;;
esac
