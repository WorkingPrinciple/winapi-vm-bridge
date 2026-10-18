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
grep -q 'DLL that exists in Windows' README.md
grep -q 'kernel drivers' docs/generic-adapters.md
if grep -R -E '(xuid|gamertag|token|signature).*[=:][[:space:]]*[0-9A-Za-z+/]{20,}' \
    --exclude-dir=.git .; then
  echo "Possible sensitive fixture found" >&2
  exit 1
fi
echo "portable tests passed"
