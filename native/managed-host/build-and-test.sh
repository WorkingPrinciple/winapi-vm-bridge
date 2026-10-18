#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out="$root/out/managed-host"
rm -rf "$out"

build_one() {
  destination=$1
  mkdir -p "$destination"
  x86_64-w64-mingw32-g++ \
    -std=c++20 -Wall -Wextra -Werror -O2 -static \
    -Wl,--no-insert-timestamp,--image-base,0x186000000 \
    -shared -I"$root/native/managed-host/include" \
    "$root/native/managed-host/src/wvb_managed_host.cpp" \
    -lbcrypt \
    -o "$destination/wvb_managed_host.dll"
  x86_64-w64-mingw32-g++ \
    -std=c++20 -Wall -Wextra -Werror -O2 -static \
    -Wl,--no-insert-timestamp,--image-base,0x187000000 \
    -I"$root/native/managed-host/include" \
    "$root/native/managed-host/src/wvb_managed_host.cpp" \
    "$root/native/managed-host/tests/config_rejection.cpp" \
    -lbcrypt \
    -o "$destination/config_rejection.exe"
  x86_64-w64-mingw32-g++ \
    -std=c++20 -Wall -Wextra -Werror -O2 -static -municode \
    -Wl,--no-insert-timestamp,--image-base,0x188000000 \
    -I"$root/native/managed-host/include" \
    "$root/native/managed-host/src/wvb_managed_host.cpp" \
    "$root/native/managed-host/tests/managed_roundtrip.cpp" \
    -lbcrypt \
    -o "$destination/managed_roundtrip.exe"
}

build_one "$out/a"
build_one "$out/b"

for file in wvb_managed_host.dll config_rejection.exe managed_roundtrip.exe; do
  test "$(shasum -a 256 "$out/a/$file" | cut -d' ' -f1)" = \
       "$(shasum -a 256 "$out/b/$file" | cut -d' ' -f1)"
done

x86_64-w64-mingw32-objdump -p "$out/a/wvb_managed_host.dll" |
  tr -d '\r' |
  grep -q '[[:space:]]wvb_managed_host_create$'
x86_64-w64-mingw32-objdump -p "$out/a/wvb_managed_host.dll" |
  tr -d '\r' |
  grep -q '[[:space:]]wvb_managed_host_dispatch$'

if command -v wine >/dev/null 2>&1; then
  (cd "$out/a" && wine ./config_rejection.exe)
elif [ -x /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine ]; then
  (cd "$out/a" &&
    /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine \
      --bottle XOdeLabRPC ./config_rejection.exe)
else
  echo "Windows runner unavailable; CLR host binaries built but not executed" >&2
  exit 2
fi

echo "managed host build tests passed"
