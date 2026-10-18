#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
bundle="$root/external/whiny/v0.3.0/frozen-bundles/native-scalar"
out="$root/out/whiny-native-scalar"
rm -rf "$out"

build_one() {
  destination=$1
  mkdir -p "$destination/target"
  cp "$bundle/target/native_math.dll" "$destination/target/native_math.dll"
  x86_64-w64-mingw32-g++ \
    -std=c++20 -Wall -Wextra -Werror -O2 -static \
    -Wl,--no-insert-timestamp,--image-base,0x189000000 \
    -shared "$bundle/dispatcher.generated.cpp" \
    -o "$destination/dispatcher.dll"
  x86_64-w64-mingw32-g++ \
    -std=c++20 -Wall -Wextra -Werror -O2 -static \
    -Wl,--no-insert-timestamp \
    "$root/native/fixtures/whiny-native-scalar/runner_test.cpp" \
    -o "$destination/runner_test.exe"
}

build_one "$out/a"
build_one "$out/b"
for file in dispatcher.dll runner_test.exe; do
  test "$(shasum -a 256 "$out/a/$file" | cut -d' ' -f1)" = \
       "$(shasum -a 256 "$out/b/$file" | cut -d' ' -f1)"
done

wine=/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine
if command -v wine >/dev/null 2>&1; then
  (cd "$out/a" && wine ./runner_test.exe)
elif [ -x "$wine" ]; then
  (cd "$out/a" && "$wine" --bottle XOdeLabRPC ./runner_test.exe)
else
  echo "Windows runner unavailable; frozen native bundle built but not executed" >&2
  exit 2
fi
