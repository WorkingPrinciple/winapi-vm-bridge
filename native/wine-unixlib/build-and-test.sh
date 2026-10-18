#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out="$root/out/wine-unixlib"
rm -rf "$out"
mkdir -p "$out"

x86_64-w64-mingw32-gcc \
  -std=c17 -Wall -Wextra -Werror -O2 -static -municode \
  -I"$root/native/wine-unixlib/include" \
  "$root/native/wine-unixlib/src/wvb_autoconfig.c" \
  "$root/native/wine-unixlib/tests/autoconfig_test.c" \
  -o "$out/autoconfig_test.exe"

"$root/native/macos-keychain/build-and-test.sh"
account="wine-unixlib-$$"
unixlib="$root/out/macos-keychain/wvb_client_ffi.so"
wine=/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine
trap '"$root/out/macos-keychain/keychain_fixture" delete "$account"' EXIT
"$root/out/macos-keychain/keychain_fixture" store "$account"
windows_path=$("$wine" --bottle XOdeLabRPC winepath -w "$unixlib")
set +e
probe=$("$wine" --bottle XOdeLabRPC "$out/autoconfig_test.exe" \
  "$windows_path" "$account" 2>&1)
status=$?
set -e
printf '%s\n' "$probe"
if [ "$status" -eq 0 ]; then
  echo "Wine unixlib automatic configuration test passed"
elif [ "$status" -eq 77 ] &&
     printf '%s\n' "$probe" |
       grep -q 'wine-unixlib-runtime=unavailable status=-3'; then
  echo "Wine unixlib runtime loading unavailable; source/build fails closed"
else
  exit "$status"
fi
