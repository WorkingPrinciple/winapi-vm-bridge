#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
out="$root/out/acceptance/managed-roundtrip"
runtime="$root/out/acceptance/windows-dotnet8-x64"
bundle="$root/external/whiny/v0.3.0/frozen-bundles/managed-scalar"
execution="$root/runtime-artifacts/whiny-v0.3.0/managed-scalar"
pin="$root/setup/runtime-pins/windows-dotnet8-x64.json"
bottle=${WVB_CROSSOVER_BOTTLE:-XOdeLabRPC}
wine=/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine
hosted_wine="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/CrossOver-Hosted Application/wine"

if [ ! -x "$wine" ]; then
  echo "CrossOver runner unavailable" >&2
  exit 2
fi

"$root/setup/provision_windows_dotnet_runtime.py"
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$pin")
"$root/native/managed-host/build-and-test.sh"
cargo build --target x86_64-pc-windows-gnu \
  -p wvb-managed-host --example windows_dispatch --release
cargo build -p wvb-managed-e2e --release
cargo build --target x86_64-pc-windows-gnu -p wvb-managed-e2e --release
rm -rf "$out"
mkdir -p "$out"
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
  dotnet build "$bundle/ExampleManagedMath.WhinyDispatcher.csproj" \
    -c Release --nologo
cmp "$bundle/bin/Release/net8.0-windows/ExampleManagedMath.WhinyDispatcher.dll" \
  "$execution/ExampleManagedMath.WhinyDispatcher.dll"
cmp "$bundle/bin/Release/net8.0-windows/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json" \
  "$execution/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json"
cp "$root/out/managed-host/a/managed_roundtrip.exe" "$out/"
cp "$root/out/managed-host/a/wvb_managed_host.dll" "$out/"
cp "$root/target/x86_64-pc-windows-gnu/release/examples/windows_dispatch.exe" "$out/"
cp "$root/target/x86_64-pc-windows-gnu/release/wvb-managed-e2e.exe" "$out/"

winpath() {
  "$wine" --bottle "$bottle" winepath -w "$1"
}
dotnet_root=$(winpath "$runtime/dotnet")
nethost=$(winpath "$runtime/host/nethost.dll")
runtime_dir="$execution"
runtimeconfig=$(winpath "$runtime_dir/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json")
dispatcher=$(winpath "$runtime_dir/ExampleManagedMath.WhinyDispatcher.dll")
target=$(winpath "$runtime_dir/Example.ManagedMath.dll")
nethost_hash=$(shasum -a 256 "$runtime/host/nethost.dll" | cut -d' ' -f1)
hostfxr_hash=$(shasum -a 256 "$runtime/dotnet/host/fxr/$version/hostfxr.dll" | cut -d' ' -f1)
runtime_hash=$(shasum -a 256 "$runtime_dir/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json" | cut -d' ' -f1)
dispatcher_hash=$(shasum -a 256 "$runtime_dir/ExampleManagedMath.WhinyDispatcher.dll" | cut -d' ' -f1)
target_hash=$(shasum -a 256 "$runtime_dir/Example.ManagedMath.dll" | cut -d' ' -f1)
host_hash=$(shasum -a 256 "$root/out/managed-host/a/wvb_managed_host.dll" | cut -d' ' -f1)
rust_adapter_hash=$(shasum -a 256 "$out/windows_dispatch.exe" | cut -d' ' -f1)
windows_broker_hash=$(shasum -a 256 "$out/wvb-managed-e2e.exe" | cut -d' ' -f1)
mac_client_hash=$(shasum -a 256 "$root/target/release/wvb-managed-e2e" | cut -d' ' -f1)

"$wine" --bottle "$bottle" "$out/managed_roundtrip.exe" \
  "$dotnet_root" \
  "$nethost" "$nethost_hash" "$hostfxr_hash" \
  "$runtimeconfig" "$runtime_hash" \
  "$dispatcher" "$dispatcher_hash" \
  "$target" "$target_hash"
host_dll=$(winpath "$out/wvb_managed_host.dll")
"$wine" --bottle "$bottle" "$out/windows_dispatch.exe" \
  "$host_dll" "$host_hash" \
  "$dotnet_root" \
  "$nethost" "$nethost_hash" "$hostfxr_hash" \
  "$runtimeconfig" "$runtime_hash" \
  "$dispatcher" "$dispatcher_hash" \
  "$target" "$target_hash"

adapter_hash=$(shasum -a 256 "$bundle/contract.canonical.json" | cut -d' ' -f1)
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
python3 -c 'import json,sys; from pathlib import Path; keys=["hostDll","hostDllSha256","dotnetRoot","nethostPath","nethostSha256","hostfxrSha256","runtimeConfigPath","runtimeConfigSha256","dispatcherAssemblyPath","dispatcherAssemblySha256","targetAssemblyPath","targetAssemblySha256"]; data={"address":sys.argv[2],"adapterHash":sys.argv[3]}; data.update(dict(zip(keys,sys.argv[4:]))); Path(sys.argv[1]).write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")' \
  "$out/e2e-config.json" "127.0.0.1:$port" "$adapter_hash" \
  "$host_dll" "$host_hash" "$dotnet_root" \
  "$nethost" "$nethost_hash" "$hostfxr_hash" \
  "$runtimeconfig" "$runtime_hash" \
  "$dispatcher" "$dispatcher_hash" "$target" "$target_hash"
windows_config=$(winpath "$out/e2e-config.json")
"$root/setup/run_cross_platform_managed_e2e.py" \
  --wine "$wine" \
  --bottle "$bottle" \
  --server "$out/wvb-managed-e2e.exe" \
  --windows-config "$windows_config" \
  --client "$root/target/release/wvb-managed-e2e" \
  --config "$out/e2e-config.json"

crossover_version=$("$hosted_wine" --version |
  awk -F': ' '/Product Version:/ {print $2; exit}')
python3 -c 'import json,sys; from pathlib import Path; receipt={"schemaVersion":1,"runtimeVersion":sys.argv[2],"runtimeRid":"win-x64","crossOverVersion":sys.argv[3],"bottle":sys.argv[4],"topology":"encrypted canonical TCP over local CrossOver bottle; not a Windows VM","result":42,"nativeHarness":"PASS","rustTypedDispatchAdapter":"PASS","encryptedCanonicalTcp":"PASS","status":"PASS","hashes":{"nethost":sys.argv[5],"hostfxr":sys.argv[6],"runtimeconfig":sys.argv[7],"dispatcherAssembly":sys.argv[8],"targetAssembly":sys.argv[9],"nativeHost":sys.argv[10],"rustAdapter":sys.argv[11],"windowsBroker":sys.argv[12],"macClient":sys.argv[13]}}; Path(sys.argv[1]).write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")' \
  "$out/receipt.json" "$version" "$crossover_version" "$bottle" \
  "$nethost_hash" "$hostfxr_hash" "$runtime_hash" \
  "$dispatcher_hash" "$target_hash" "$host_hash" "$rust_adapter_hash" \
  "$windows_broker_hash" "$mac_client_hash"

echo "managed-clr-roundtrip=ok result=42 receipt=$out/receipt.json"
