#!/bin/sh
set -eu
./mac/doctor.sh | grep -q 'doctor=ok'
./bin/winapi-vm-bridge adapters --json | grep -q '"core"'
./bin/winapi-vm-bridge adapters --json | grep -q '"windows.kernel32"'
python3 -m unittest tests.test_sdk
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
./bin/winapi-vm-bridge generate examples/example-math/adapter.json --out "$tmp"
test -f "$tmp/example-math/IMPLEMENTATION_TASK.md"
./bin/winapi-vm-bridge inspect \
  --header examples/inspection/vendor.h \
  --out "$tmp/inspection.json"
grep -q '"requiresTraceOrAnnotation"' "$tmp/inspection.json"
mkdir -p "$tmp/managed"
cargo run -q -p wvb-generate -- \
  --contract examples/managed-scalar/adapter.json \
  --out "$tmp/managed"
cmp "$tmp/managed/Example.ManagedMath.csproj" \
  managed/fixtures/example-managed-math/Example.ManagedMath.csproj
cmp "$tmp/managed/Proxy.generated.cs" \
  managed/fixtures/example-managed-math/Proxy.generated.cs
cmp "$tmp/managed/contract.canonical.json" \
  managed/fixtures/example-managed-math/contract.canonical.json
if command -v dotnet >/dev/null 2>&1; then
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build "$tmp/managed/Example.ManagedMath.csproj" \
      -c Release --nologo
fi
grep -q 'DLL that exists in Windows' README.md
grep -q 'kernel drivers' docs/generic-adapters.md
if grep -R -E '(xuid|gamertag|token|signature).*[=:][[:space:]]*[0-9A-Za-z+/]{20,}' \
    --exclude-dir=.git \
    --exclude-dir=target \
    --exclude-dir=out \
    --exclude-dir=bin \
    --exclude-dir=obj \
    --exclude-dir=__pycache__ .; then
  echo "Possible sensitive fixture found" >&2
  exit 1
fi
echo "portable tests passed"
