#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
out="$root/out/c-dll"
rm -rf "$out"
build_one() {
  destination=$1
  mkdir -p "$destination/generated"
  cargo run --quiet -p wvb-generate -- \
    --contract "$root/native/fixtures/c-dll/adapter.json" \
    --out "$destination/generated"

  x86_64-w64-mingw32-gcc -shared -O2 \
    -Wl,--no-insert-timestamp,--image-base,0x180000000 \
    "$root/native/fixtures/c-dll/vendor.c" \
    -o "$destination/vendor.dll"

  x86_64-w64-mingw32-g++ -shared -O2 -std=c++17 \
    -Wl,--no-insert-timestamp,--image-base,0x181000000 \
    "$destination/generated/dispatcher.generated.cpp" \
    -o "$destination/example_math_dispatch.dll"

  x86_64-w64-mingw32-gcc -shared -O2 \
    -Wl,--no-insert-timestamp,--image-base,0x182000000 \
    -I"$root/native/include" \
    "$destination/generated/proxy.generated.c" \
    "$root/native/fixtures/c-dll/runtime_stub.c" \
    "$destination/generated/proxy.generated.def" \
    -Wl,--out-implib,"$destination/libexample_math.a" \
    -o "$destination/example_math.dll"

  x86_64-w64-mingw32-gcc -O2 -Wl,--no-insert-timestamp \
    "$root/native/fixtures/c-dll/test_app.c" \
    -L"$destination" -lexample_math \
    -o "$destination/test_app.exe"
}

build_one "$out/a"
build_one "$out/b"

for file in vendor.dll example_math_dispatch.dll example_math.dll test_app.exe; do
  test "$(shasum -a 256 "$out/a/$file" | cut -d' ' -f1)" = \
       "$(shasum -a 256 "$out/b/$file" | cut -d' ' -f1)"
done
cmp "$out/a/generated/proxy.generated.c" "$out/b/generated/proxy.generated.c"
cmp "$out/a/generated/dispatcher.generated.cpp" "$out/b/generated/dispatcher.generated.cpp"
cmp "$out/a/generated/contract.canonical.json" "$out/b/generated/contract.canonical.json"

x86_64-w64-mingw32-objdump -p "$out/a/example_math.dll" |
  tr -d '\r' |
  grep -q '[[:space:]]ExampleAdd$'

if command -v wine >/dev/null 2>&1; then
  (cd "$out/a" && wine ./test_app.exe)
elif [ -x /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine ]; then
  (cd "$out/a" && /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine \
    --bottle XOdeLabRPC ./test_app.exe)
else
  echo "Windows runner unavailable; binaries built but runtime parity not proven" >&2
  exit 2
fi
