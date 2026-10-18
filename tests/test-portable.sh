#!/bin/sh
set -eu
./mac/doctor.sh | grep -q 'doctor=ok'
./bin/winapi-vm-bridge adapters --json | grep -q '"core"'
./bin/winapi-vm-bridge adapters --json | grep -q '"windows.kernel32"'
python3 -m unittest \
  tests.test_sdk \
  tests.test_runtime_acceptance \
  tests.test_runtime_metadata
cargo test -q -p wvb-admission -p wvb-integrity -p wvb-operations \
  -p wvb-package -p wvb-state -p wvb-transfer -p wvb-exe
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
cmp "$tmp/managed/Example.ManagedMath.WvbDispatcher.csproj" \
  managed/fixtures/example-managed-math/Example.ManagedMath.WvbDispatcher.csproj
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
  mkdir -p "$tmp/managed/lib"
  cp "$target" "$tmp/managed/lib/Example.ManagedMath.dll"
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build "$tmp/managed/Example.ManagedMath.WvbDispatcher.csproj" \
      -c Release --nologo
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
  cmp "$tmp/inspected-generated/Example.ManagedMath.WvbDispatcher.csproj" \
    managed/fixtures/example-managed-math/Example.ManagedMath.WvbDispatcher.csproj
  mkdir -p "$tmp/inspected-generated/lib"
  cp "$target" "$tmp/inspected-generated/lib/Example.ManagedMath.dll"
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build \
      "$tmp/inspected-generated/Example.ManagedMath.WvbDispatcher.csproj" \
      -c Release --nologo
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
./native/managed-host/build-and-test.sh
./native/fixtures/native-exe/build-and-test.sh
python3 -c 'import json; from pathlib import Path; p=Path("setup/runtime-pins/windows-dotnet8-x64.json"); v=json.loads(p.read_text(encoding="utf-8")); assert v["version"]=="8.0.32"; assert v["rid"]=="win-x64"; assert len(v["runtime"]["sha256"])==64; assert len(v["runtime"]["sha512"])==128; assert len(v["nethostPackage"]["sha256"])==64; assert len(v["files"]["hostfxr"]["sha256"])==64; assert len(v["files"]["nethost"]["sha256"])==64'
python3 -c 'compile(open("setup/provision_windows_dotnet_runtime.py", encoding="utf-8").read(), "setup/provision_windows_dotnet_runtime.py", "exec")'
python3 -c 'compile(open("setup/run_cross_platform_managed_e2e.py", encoding="utf-8").read(), "setup/run_cross_platform_managed_e2e.py", "exec")'
python3 -c 'compile(open("setup/run_utm_deploy.py", encoding="utf-8").read(), "setup/run_utm_deploy.py", "exec")'
python3 -c 'compile(open("setup/run_utm_managed_e2e.py", encoding="utf-8").read(), "setup/run_utm_managed_e2e.py", "exec")'
python3 -c 'compile(open("setup/run_utm_acceptance.py", encoding="utf-8").read(), "setup/run_utm_acceptance.py", "exec")'
python3 -c 'compile(open("setup/generate_runtime_metadata.py", encoding="utf-8").read(), "setup/generate_runtime_metadata.py", "exec")'
test -x native/managed-host/run-managed-roundtrip.sh
test -x setup/provision_windows_dotnet_runtime.py
test -x setup/run_cross_platform_managed_e2e.py
test -x setup/run_utm_deploy.py
test -x setup/run_utm_managed_e2e.py
test -x setup/run_utm_acceptance.py
test -x setup/generate_runtime_metadata.py
grep -q 'runtime and execution plane' README.md
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
