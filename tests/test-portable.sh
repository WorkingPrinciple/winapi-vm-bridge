#!/bin/sh
set -eu
./mac/doctor.sh | grep -q 'doctor=ok'
./bin/winapi-vm-bridge call core.ping --json | grep -q '"ok":true'
./bin/winapi-vm-bridge adapters --json | grep -q '"core.mock"'
grep -q 'Windows DLL' README.md
grep -q 'kernel drivers' docs/generic-adapters.md
if grep -R -E '(xuid|gamertag|token|signature).*[=:][[:space:]]*[0-9A-Za-z+/]{20,}' \
    --exclude-dir=.git .; then
  echo "Possible sensitive fixture found" >&2
  exit 1
fi
echo "portable tests passed"

