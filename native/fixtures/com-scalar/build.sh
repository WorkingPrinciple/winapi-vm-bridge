#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
out=${WVB_COM_OUT:-"$root/out/com-scalar"}
case "$out" in "$root/out/"*) ;; *) echo "output must be inside this worktree/out" >&2; exit 2 ;; esac
: "${WVB_WIDL:?Select the exact own-Wine SDK widl}"
: "${WVB_COM_IMPORT_LIBRARY:?Select the updated builtin import archive}"
mkdir -p "$out"
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -O2 -static \
  -Wl,--no-insert-timestamp "$root/native/fixtures/com-scalar/server.cpp" \
  -lole32 -luuid -o "$out/com_scalar.exe"
"$WVB_WIDL" -m64 -t -o "$out/object.tlb" "$root/native/fixtures/com-scalar/object.idl"
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -O2 -static -municode \
  -Wl,--no-insert-timestamp -I"$root/native/include" \
  "$root/native/fixtures/com-scalar/proxy_call.cpp" "$WVB_COM_IMPORT_LIBRARY" \
  -luuid -o "$out/proxy_call.exe"
