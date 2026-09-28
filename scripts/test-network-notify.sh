#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
notify_test=$(mktemp -d)
trap 'rm -rf "$notify_test"' EXIT HUP INT TERM
# Optional native ownership/race instrumentation, e.g. SANITIZER=thread sh ...
san_flag=
case "${SANITIZER:-}" in
  "") ;;
  address|thread) san_flag="-fsanitize=$SANITIZER" ;;
  *) echo "SANITIZER must be address or thread" >&2; exit 2 ;;
esac
for mode in public multiple; do
  define=
  if [ "$mode" = multiple ]; then define=-DIN_NETWORK_MULTIPLE; fi
  xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Werror ${san_flag:+$san_flag} ${define:+$define} \
    "$root/tests/network_notify.m" -framework Foundation -framework Network \
    -o "$notify_test/network-notify-$mode"
  "$notify_test/network-notify-$mode"
done
xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Werror ${san_flag:+$san_flag} \
  "$root/tests/network_multiple.m" -framework Foundation -framework Network \
  -o "$notify_test/network-multiple"
status=0
"$notify_test/network-multiple" || status=$?
# A missing SPI is an explicit skip, never a silent backend fallback.
if [ "$status" -ne 0 ] && [ "$status" -ne 77 ]; then exit "$status"; fi
