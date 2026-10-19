#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out="$root/out/macos-keychain"
rm -rf "$out"
mkdir -p "$out"

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

"$out/keychain_roundtrip"
nm -gU "$out/wvb_client_ffi.so" |
  grep -q '_wvb_unix_load_runtime_config$'
nm -gU "$out/wvb_client_ffi.so" |
  grep -q '___wine_unix_call_funcs$'
echo "macOS Keychain unixlib source tests passed"
