#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
notify_test=$(mktemp -d)
trap 'rm -rf "$notify_test"' EXIT HUP INT TERM
xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Werror \
  "$root/tests/network_notify.m" -framework Foundation -framework Network \
  -o "$notify_test/network-notify"
"$notify_test/network-notify"
