#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
out="$root/out/native-exe"
rm -rf "$out"
mkdir -p "$out/a" "$out/b"

build_one() {
  destination=$1
  x86_64-w64-mingw32-gcc -std=c17 -Wall -Wextra -Werror -O2 -static \
    -Wl,--no-insert-timestamp,--image-base,0x189000000 \
    "$root/native/fixtures/native-exe/vendor_cli.c" \
    -o "$destination/vendor-cli.exe"
  x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror -O2 -static \
    -municode -Wl,--no-insert-timestamp,--image-base,0x18a000000 \
    "$root/native/fixtures/native-exe/runner_test.cpp" -lbcrypt \
    -o "$destination/runner-test.exe"
}

build_one "$out/a"
build_one "$out/b"
cmp "$out/a/vendor-cli.exe" "$out/b/vendor-cli.exe"
cmp "$out/a/runner-test.exe" "$out/b/runner-test.exe"
hash=$(shasum -a 256 "$out/a/vendor-cli.exe" | cut -d' ' -f1)
if command -v wine >/dev/null 2>&1; then
  wine "$out/a/runner-test.exe" "$out/a/vendor-cli.exe" "$hash"
elif [ -x /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine ]; then
  /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine \
    --bottle XOdeLabRPC "$out/a/runner-test.exe" \
    "$out/a/vendor-cli.exe" "$hash"
else
  echo "Windows runner unavailable; native EXE execution skipped" >&2
  [ "${WVB_REQUIRE_WINDOWS_RUNNER:-0}" != 1 ] || exit 2
fi
echo "native EXE fixture tests passed"
