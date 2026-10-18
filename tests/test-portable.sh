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
cmp "$tmp/managed/Dispatcher.generated.cs" \
  managed/fixtures/example-managed-math/Dispatcher.generated.cs
cmp "$tmp/managed/contract.canonical.json" \
  managed/fixtures/example-managed-math/contract.canonical.json
if command -v dotnet >/dev/null 2>&1; then
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build "$tmp/managed/Example.ManagedMath.csproj" \
      -c Release --nologo
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build managed/tools/Wvb.ManagedInspector/Wvb.ManagedInspector.csproj \
      -c Release --nologo
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build managed/fixtures/vendor-managed-math/Vendor.ManagedMath.csproj \
      -c Release --nologo
  target=managed/fixtures/vendor-managed-math/bin/Release/net8.0-windows/Example.ManagedMath.dll
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet run \
      --project managed/tools/Wvb.ManagedInspector/Wvb.ManagedInspector.csproj \
      -c Release --no-build -- \
      --assembly "$target" \
      --adapter-id example.managed_math \
      --relative-path lib/Example.ManagedMath.dll \
      --out "$tmp/inspected-managed.json"
  python3 -c 'import hashlib,json,sys; c=json.load(open(sys.argv[1], encoding="utf-8")); b=open(sys.argv[2],"rb").read(); assert c["family"]=="dot-net-assembly"; assert c["managed"]["target_framework"]=="net8.0-windows"; assert c["target"]["sha256"]==hashlib.sha256(b).hexdigest(); assert [(o["managed"]["declaring_type"],o["managed"]["member_name"]) for o in c["operations"]]==[("Example.ManagedMath.Calculator","Add")]' \
    "$tmp/inspected-managed.json" "$target"
  cargo run -q -p wvb-generate -- \
    --contract "$tmp/inspected-managed.json" \
    --out "$tmp/inspected-generated"
  cmp "$tmp/inspected-generated/Dispatcher.generated.cs" \
    managed/fixtures/example-managed-math/Dispatcher.generated.cs
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet run \
      --project managed/fixtures/managed-dispatch-oracle/ManagedDispatchOracle.csproj \
      -c Release | grep -q 'managed-dispatch-oracle=ok result=42'
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build \
      managed/fixtures/unsupported-managed-instance/Unsupported.ManagedInstance.csproj \
      -c Release --nologo
  unsupported=managed/fixtures/unsupported-managed-instance/bin/Release/net8.0-windows/Unsupported.ManagedInstance.dll
  if unsupported_output=$(DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet run \
      --project managed/tools/Wvb.ManagedInspector/Wvb.ManagedInspector.csproj \
      -c Release --no-build -- \
      --assembly "$unsupported" \
      --adapter-id unsupported.instance \
      --relative-path lib/Unsupported.ManagedInstance.dll \
      --out "$tmp/unsupported-managed.json" 2>&1); then
    echo "Managed instance inspection unexpectedly succeeded" >&2
    exit 1
  fi
  printf '%s\n' "$unsupported_output" | grep -q 'is not a static type'
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
