#!/bin/sh
# Builds upstream wg against a temporary UAPI directory; does not need root.
set -eu
scratch=$(mktemp -d /tmp/interestun-wg.XXXXXX)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
mkdir -p "$scratch/run/wireguard"
git clone --quiet https://git.zx2c4.com/wireguard-tools "$scratch/wireguard-tools"
git -C "$scratch/wireguard-tools" checkout --quiet a998407747005ea7e4e0258d96f105c97241e1d3
make -C "$scratch/wireguard-tools/src" -j4 RUNSTATEDIR="$scratch/run"
INTERESTUN_TEST_WG="$scratch/wireguard-tools/src/wg" \
INTERESTUN_TEST_UAPI_DIR="$scratch/run/wireguard" \
cargo test --locked --test uapi
