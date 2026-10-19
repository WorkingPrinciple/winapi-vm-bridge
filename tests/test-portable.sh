#!/bin/sh
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

python3 -m unittest \
  tests.test_runtime_acceptance \
  tests.test_runtime_metadata \
  tests.test_runtime_package_builder \
  tests.test_topology_benchmark \
  tests.test_windows_vm_acceptance \
  tests.test_whiny_pin

cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

mkdir -p "$tmp/runtime-package/bin"
printf 'runtime\n' > "$tmp/runtime-package/bin/wvb"
python3 - "$tmp/runtime-package/manifest.jcs" "$tmp/runtime-package/bin/wvb" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

digest = list(hashlib.sha256(Path(sys.argv[2]).read_bytes()).digest())
manifest = {
    "identifier": "winapi-vm-bridge.runtime-package.v1",
    "major": 1,
    "package_version": "0.2.0-test",
    "source_sha256": [1] * 32,
    "sbom_sha256": [2] * 32,
    "files": [{
        "relative_path": "bin/wvb",
        "sha256": digest,
        "executable": False,
    }],
}
Path(sys.argv[1]).write_text(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")),
    encoding="utf-8",
)
PY
cargo run -q -p wvb-runtime -- init-state \
  --state "$tmp/runtime-state.db" >/dev/null
cargo run -q -p wvb-runtime -- doctor \
  --state "$tmp/runtime-state.db" \
  --package-root "$tmp/runtime-package" \
  --receipt "$tmp/runtime-health.json" >/dev/null
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"]=="PASS"' \
  "$tmp/runtime-health.json"

./native/managed-host/build-and-test.sh
./native/fixtures/native-exe/build-and-test.sh
./native/fixtures/whiny-native-scalar/build-and-test.sh
./native/macos-keychain/build-and-test.sh
./native/wine-unixlib/build-and-test.sh

if command -v dotnet >/dev/null 2>&1; then
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet build \
      external/whiny/v0.3.0/frozen-bundles/managed-scalar/ExampleManagedMath.WhinyDispatcher.csproj \
      -c Release --nologo
fi

python3 -c 'import json; from pathlib import Path; p=Path("setup/runtime-pins/windows-dotnet8-x64.json"); v=json.loads(p.read_text(encoding="utf-8")); assert v["version"]=="8.0.32"; assert v["rid"]=="win-x64"; assert len(v["runtime"]["sha256"])==64; assert len(v["runtime"]["sha512"])==128; assert len(v["nethostPackage"]["sha256"])==64; assert len(v["files"]["hostfxr"]["sha256"])==64; assert len(v["files"]["nethost"]["sha256"])==64'
for script in \
  setup/provision_windows_dotnet_runtime.py \
  setup/run_cross_platform_managed_e2e.py \
  setup/build_windows_vm_acceptance.py \
  setup/run_utm_deploy.py \
  setup/run_utm_scalar_e2e.py \
  setup/run_utm_scalar_benchmark.py \
  setup/generate_windows_vm_evidence_manifest.py \
  setup/run_utm_acceptance.py \
  setup/generate_runtime_metadata.py \
  setup/build_runtime_package.py \
  setup/run_topology_benchmark.py; do
  python3 -m py_compile "$script"
  test -x "$script"
done

source_sha=$(shasum -a 256 Cargo.lock | cut -d' ' -f1)
python3 setup/generate_runtime_metadata.py \
  --source-sha256 "$source_sha" \
  --artifact Cargo.lock=Cargo.lock \
  --output "$tmp/runtime-metadata" >/dev/null
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); assert p["subject"][0]["name"]=="Cargo.lock"' \
  "$tmp/runtime-metadata/runtime.provenance.json"

test -x setup/wvb-bootstrap-macos
grep -q 'WVB_SIGNATURE_VERIFIER is required' setup/wvb-bootstrap-macos
grep -q 'WVB_SIGNATURE_VERIFIER is required' setup/wvb-bootstrap-windows.ps1
grep -q 'function Invoke-Native' setup/wvb-bootstrap-windows.ps1
grep -q "Copy-Item -LiteralPath .*installedCli" setup/wvb-bootstrap-windows.ps1
grep -q 'install -m 755 .*wvb-package' setup/wvb-bootstrap-macos
sh -n setup/wvb-bootstrap-macos

grep -q 'runtime and execution plane' README.md
grep -q 'Whiny exclusively owns' docs/implementation-ledger.md
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
