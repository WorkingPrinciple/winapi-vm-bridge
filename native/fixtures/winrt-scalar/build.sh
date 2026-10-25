#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
out=${WVB_WINRT_OUT:-"$root/out/winrt-scalar"}
case "$out" in "$root/out/"*) ;; *) echo "output must be inside this worktree/out" >&2; exit 2 ;; esac
: "${WVB_WINRT_IMPORT_LIBRARY:?Select the existing matched builtin import archive}"
mkdir -p "$out/empty-source"
test ! -e "$out/Wvb.Test.winmd"
dotnet restore "$root/native/fixtures/winrt-scalar/Winmd.csproj" \
  --artifacts-path "$out/tool" --source "$out/empty-source" --verbosity quiet
dotnet run --project "$root/native/fixtures/winrt-scalar/Winmd.csproj" \
  --artifacts-path "$out/tool" --no-restore -- "$out/Wvb.Test.winmd"
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -O2 -static -shared \
  -Wl,--no-insert-timestamp "$root/native/fixtures/winrt-scalar/component.cpp" \
  -lole32 -lruntimeobject -luuid -o "$out/Wvb.Test.WvbScalarRuntimeClass.dll"
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -O2 -static -municode \
  -Wl,--no-insert-timestamp "$root/native/fixtures/winrt-scalar/oracle.cpp" \
  -lole32 -lruntimeobject -luuid -o "$out/winrt_oracle.exe"
cp "$root/native/fixtures/winrt-scalar/activation.manifest" "$out/activation.manifest"
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -O2 -static -municode \
  -Wl,--no-insert-timestamp -I"$root/native/include" \
  "$root/native/fixtures/winrt-scalar/proxy_call.cpp" "$WVB_WINRT_IMPORT_LIBRARY" \
  -lole32 -lruntimeobject -luuid -o "$out/proxy_call.exe"
