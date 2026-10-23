#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out="$root/out/wine-unixlib"
mkdir -p "$out"

python3 - "$root/native/wine-unixlib/run-loader-probe.py" <<'PY'
import ast
from pathlib import Path
import re
import sys
tree = ast.parse(Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1])
assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "BUILTIN_TRACE"
                          for target in node.targets))
predicate = re.compile(ast.literal_eval(assignment.value.args[0]), re.IGNORECASE | re.MULTILINE)
line = r'0012:0024:trace:loaddll:build_module Loaded L"C:\\windows\\system32\\wvb_autoconfig.dll" at 0000000012340000: builtin'
assert predicate.search(line)
assert not predicate.search(line.replace(": builtin", ": native"))
assert not predicate.search(line.replace("wvb_autoconfig.dll", "other.dll"))
PY

# These checks neither launch Wine nor read/write credential storage.
clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/wine-unixlib/tests/sdk" \
  -I"$root/native/wine-unixlib/include" \
  -I"$root/native/macos-keychain/include" \
  "$root/native/wine-unixlib/src/wvb_autoconfig.c" \
  "$root/native/wine-unixlib/src/wvb_builtin.c" \
  "$root/native/wine-unixlib/tests/builtin_test.c" \
  -o "$out/builtin_source_test"
"$out/builtin_source_test"

x86_64-w64-mingw32-gcc \
  -std=c17 -Wall -Wextra -Werror -O2 -static -municode \
  -I"$root/native/wine-unixlib/include" \
  "$root/native/wine-unixlib/src/wvb_autoconfig.c" \
  "$root/native/wine-unixlib/tests/autoconfig_test.c" \
  -o "$out/autoconfig_test.exe"

x86_64-w64-mingw32-gcc \
  -std=c17 -Wall -Wextra -Werror -O2 -static -municode \
  -Wl,--no-insert-timestamp \
  "$root/native/wine-unixlib/tests/loader_probe.c" \
  -o "$out/loader_probe.exe"

if [ -z "${WVB_WINEGCC:-}" ]; then
  echo "Builtin source tests and PE caller build passed; builtin pair NOT built: select the exact runtime's Wine SDK with WVB_WINEGCC." >&2
  [ "${WVB_REQUIRE_BUILTIN_BUILD:-0}" != 1 ] || exit 2
  exit 0
fi

mkdir -p "$out/lib/wine/x86_64-windows" "$out/lib/wine/x86_64-unix"
"$WVB_WINEGCC" -b x86_64-w64-mingw32 -m64 -shared \
  -std=c17 -Wall -Wextra -Werror -O2 -Wl,--wine-builtin \
  -I"$root/native/wine-unixlib/include" \
  -I"$root/native/macos-keychain/include" \
  "$root/native/wine-unixlib/src/wvb_builtin.c" \
  "$root/native/wine-unixlib/src/wvb_autoconfig.spec" \
  -lntdll \
  -o "$out/lib/wine/x86_64-windows/wvb_autoconfig.dll"

clang -arch x86_64 -std=c17 -Wall -Wextra -Werror -O2 \
  -fvisibility=hidden -dynamiclib \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/src/wvb_unixlib.c" \
  -framework Security -framework CoreFoundation \
  -o "$out/lib/wine/x86_64-unix/wvb_autoconfig.so"

echo "Builtin pair built from selected Wine SDK; runtime load/Keychain/Bridge acceptance NOT performed."
