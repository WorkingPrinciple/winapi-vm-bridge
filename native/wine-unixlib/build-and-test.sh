#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out="${WVB_BUILD_OUT:-"$root/out/wine-unixlib-static"}"
case "$out" in
  "$root/out/"*) ;;
  *) echo "WVB_BUILD_OUT must be inside the current worktree's out directory." >&2; exit 2 ;;
esac
set --
if [ -n "${WVB_WINE_SOURCE:-}" ]; then
  [ -n "${WVB_WINE_SOURCE_COMMIT:-}" ] &&
    [ -n "${WVB_WINEGCC:-}" ] && [ -n "${WVB_WINEBUILD:-}" ] || {
    echo "Source-bound SDK requires WVB_WINE_SOURCE_COMMIT, WVB_WINEGCC and WVB_WINEBUILD." >&2
    exit 2
  }
  [ "$(git -C "$WVB_WINE_SOURCE" rev-parse HEAD)" = "$WVB_WINE_SOURCE_COMMIT" ] &&
    [ -z "$(git -C "$WVB_WINE_SOURCE" status --porcelain)" ] || {
    echo "Selected Wine source identity is not the exact clean commit." >&2
    exit 2
  }
  [ -f "$WVB_WINE_SOURCE/include/wine/unixlib.h" ] || {
    echo "Selected source lacks the Wine Unix-call ABI header." >&2
    exit 2
  }
  set -- -I"$WVB_WINE_SOURCE/include"
fi
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

python3 -B "$root/native/wine-unixlib/tests/loader_probe_test.py"
python3 -B "$root/native/wine-unixlib/tests/client_closure_test.py" --self-test

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

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/wine-unixlib/tests/sdk" \
  -I"$root/native/wine-unixlib/include" -I"$root/native/include" \
  -Dwvb_client_configure=wvb_test_pe_configure \
  -Dwvb_client_bind_operation=wvb_test_pe_bind \
  -Dwvb_client_call=wvb_test_pe_call \
  -Dwvb_client_call_ex=wvb_test_pe_call_ex \
  -Dwvb_client_reset=wvb_test_pe_reset \
  -Dwvb_client_handle_close=wvb_test_pe_handle_close \
  -c "$root/native/wine-unixlib/src/wvb_client_builtin.c" \
  -o "$out/client_builtin_test.o"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/wine-unixlib/tests/sdk" \
  -I"$root/native/wine-unixlib/include" -I"$root/native/include" \
  -I"$root/native/macos-keychain/include" \
  "$out/client_builtin_test.o" \
  "$root/native/wine-unixlib/src/wvb_client_unixlib.c" \
  "$root/native/wine-unixlib/tests/client_forwarding_test.c" \
  -o "$out/client_forwarding_source_test"
"$out/client_forwarding_source_test"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/wine-unixlib/tests/sdk" -I"$root/native/include" \
  "$root/native/wine-unixlib/tests/scalar_call_probe.c" \
  "$root/native/wine-unixlib/tests/scalar_call_probe_test.c" \
  -o "$out/scalar_call_probe_source_test"
"$out/scalar_call_probe_source_test"

clang -std=c17 -Wall -Wextra -Werror -O2 \
  -I"$root/native/wine-unixlib/tests/sdk" \
  "$root/native/wine-unixlib/tests/loader_probe.c" \
  "$root/native/wine-unixlib/tests/loader_probe_source_test.c" \
  -o "$out/loader_probe_source_test"
"$out/loader_probe_source_test"

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
winebuild="${WVB_WINEBUILD:-"$(dirname "$WVB_WINEGCC")/winebuild"}"
if [ ! -x "$winebuild" ]; then
  echo "Select the same SDK's winebuild with WVB_WINEBUILD for spec-driven import thunks." >&2
  exit 2
fi
client_library="${WVB_HOST_CLIENT_LIB:-"$out/host-client/x86_64-apple-darwin/debug/libwvb_client_ffi.a"}"
if [ -z "${WVB_HOST_CLIENT_LIB:-}" ]; then
  cargo build --manifest-path "$root/Cargo.toml" --target-dir "$out/host-client" \
    -p wvb-client-ffi --target x86_64-apple-darwin --locked --offline --quiet
fi
if [ ! -f "$client_library" ]; then
  echo "Missing actual x86_64-apple-darwin Rust static archive: $client_library" >&2
  exit 2
fi
python3 - "$client_library" <<'PY'
from pathlib import Path
import sys
with Path(sys.argv[1]).open("rb") as library:
    if library.read(8) != b"!<arch>\n":
        print("WVB_HOST_CLIENT_LIB must be the real Rust static archive, not a dylib.", file=sys.stderr)
        raise SystemExit(2)
PY
if ! lipo -verify_arch x86_64 "$client_library"; then
  echo "Build the actual x86_64-apple-darwin wvb-client-ffi static archive first; no architecture fallback." >&2
  exit 2
fi
"$WVB_WINEGCC" --winebuild "$winebuild" -b x86_64-w64-mingw32 -m64 -shared \
  -std=c17 -Wall -Wextra -Werror -O2 -Wl,--wine-builtin \
  "$@" \
  -I"$root/native/wine-unixlib/include" \
  -I"$root/native/include" \
  -I"$root/native/macos-keychain/include" \
  "$root/native/wine-unixlib/src/wvb_builtin.c" \
  "$root/native/wine-unixlib/src/wvb_client_builtin.c" \
  "$root/native/wine-unixlib/src/wvb_autoconfig.spec" \
  -lntdll \
  -o "$out/lib/wine/x86_64-windows/wvb_autoconfig.dll"

"$winebuild" -b x86_64-w64-mingw32 --implib -F wvb_autoconfig.dll \
  -E "$root/native/wine-unixlib/src/wvb_autoconfig.spec" \
  -o "$out/lib/wine/x86_64-windows/libwvb_autoconfig.dll.a"

python3 -B "$root/native/wine-unixlib/tests/client_import_test.py" \
  "$root" "$out" "$out/lib/wine/x86_64-windows/libwvb_autoconfig.dll.a"

x86_64-w64-mingw32-gcc -std=c17 -Wall -Wextra -Werror -O2 \
  -static -static-libgcc -municode -Wl,--no-insert-timestamp \
  -I"$root/native/include" \
  "$root/native/wine-unixlib/tests/scalar_call_probe.c" \
  "$out/lib/wine/x86_64-windows/libwvb_autoconfig.dll.a" \
  -o "$out/scalar_call_probe.exe"
x86_64-w64-mingw32-gcc -std=c17 -Wall -Wextra -Werror -O2 \
  -static -static-libgcc -municode -Wl,--no-insert-timestamp \
  -I"$root/native/include" \
  "$root/native/fixtures/kernel32-pid/proxy_call.c" \
  "$out/lib/wine/x86_64-windows/libwvb_autoconfig.dll.a" \
  -o "$out/pid_proxy_call.exe"
python3 -B - "$root" "$out" <<'PY'
from pathlib import Path
import runpy
import sys
gate = runpy.run_path(str(Path(sys.argv[1]) / "native/wine-unixlib/tests/client_import_test.py"))
gate["require_imports"](Path(sys.argv[2]) / "scalar_call_probe.exe",
                        {"wvb_client_configure", "wvb_client_reset"})
gate["require_imports"](Path(sys.argv[2]) / "pid_proxy_call.exe",
                        {"wvb_client_configure", "wvb_client_reset"})
print("Calling PE fixture links only explicit configure/reset from builtin")
PY

clang -arch x86_64 -std=c17 -Wall -Wextra -Werror -O2 \
  -fvisibility=hidden -dynamiclib \
  -DWVB_EXTERNAL_UNIX_CALL_TABLE \
  -I"$root/native/wine-unixlib/include" -I"$root/native/include" \
  -I"$root/native/macos-keychain/include" \
  "$root/native/macos-keychain/src/wvb_keychain.c" \
  "$root/native/macos-keychain/src/wvb_unixlib.c" \
  "$root/native/wine-unixlib/src/wvb_client_unixlib.c" \
  "$client_library" \
  -liconv -lc -lm \
  -framework Security -framework CoreFoundation \
  -Wl,-install_name,@loader_path/wvb_autoconfig.so \
  -Wl,-exported_symbol,___wine_unix_call_funcs \
  -Wl,-exported_symbol,___wine_unix_call_wow64_funcs \
  -Wl,-exported_symbol,_wvb_unix_load_runtime_config \
  -o "$out/lib/wine/x86_64-unix/wvb_autoconfig.so"

python3 - "$out" <<'PY'
from pathlib import Path
import subprocess
import sys

out = Path(sys.argv[1]) / "lib/wine"
pe = out / "x86_64-windows/wvb_autoconfig.dll"
clients = {
    "wvb_client_configure", "wvb_client_bind_operation", "wvb_client_call",
    "wvb_client_call_ex", "wvb_client_reset", "wvb_client_handle_close",
}
def output(*args):
    return subprocess.check_output(args, text=True)

text = output("x86_64-w64-mingw32-objdump", "-p", str(pe))
table = text.split("[Ordinal/Name Pointer] Table", 1)[1].split("The Function Table", 1)[0]
exports = {line.split()[-1] for line in table.splitlines() if line.strip().startswith("[")}
assert exports == clients | {"wvb_builtin_load_config"}, exports
assert output("x86_64-w64-mingw32-dlltool", "-I",
              str(pe.with_name("libwvb_autoconfig.dll.a"))).strip() == "wvb_autoconfig.dll"
print("Exact PE exports/import-library name checked")
PY

python3 -B "$root/native/wine-unixlib/tests/client_closure_test.py" "$root" "$out"

echo "Builtin pair built from selected Wine SDK; runtime load/Keychain/Bridge acceptance NOT performed."
