#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
mode=${1:-}
[ -z "$mode" ] || [ "$mode" = "--source-only" ] || {
  echo "usage: build-and-test.sh [--source-only]" >&2
  exit 64
}
out=${WVB_BUILD_OUT:-"$root/out/macos-keychain"}
mkdir -p "$out"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/src/wvb_provision.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/wvb-provision"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/tests/provision_test.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/provision_test"
"$out/provision_test"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -fvisibility=hidden -dynamiclib \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/src/wvb_unixlib.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/wvb_client_ffi.so"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/src/wvb_unixlib.c" \
  "$root/native/macos-keychain/tests/keychain_roundtrip.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/keychain_roundtrip"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/tests/keychain_fixture.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/keychain_fixture"

if [ "$mode" != "--source-only" ]; then
  "$out/keychain_roundtrip"
fi
nm -gU "$out/wvb_client_ffi.so" |
  grep -q '_wvb_unix_load_runtime_config$'
nm -gU "$out/wvb_client_ffi.so" |
  grep -q '___wine_unix_call_funcs$'
echo "macOS Keychain build/source checks passed (mode=${mode:-keychain-roundtrip})"
