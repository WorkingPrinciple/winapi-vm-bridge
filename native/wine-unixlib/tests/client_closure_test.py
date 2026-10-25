"""Inspect and link relocated real artifacts only; never dlopen or execute a PE."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

CLIENTS = {
    "_wvb_client_configure", "_wvb_client_bind_operation", "_wvb_client_call",
    "_wvb_client_call_ex", "_wvb_client_reset", "_wvb_client_handle_close",
}
EXPORTS = {
    "___wine_unix_call_funcs", "___wine_unix_call_wow64_funcs",
    "_wvb_unix_load_runtime_config",
}
INSTALL_NAME = "@loader_path/wvb_autoconfig.so"
SYSTEM = {
    "/usr/lib/libSystem.B.dylib", "/usr/lib/libiconv.2.dylib",
    "/System/Library/Frameworks/Security.framework/Versions/A/Security",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
}


def output(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True,
                              timeout=60).stdout
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        raise


def libraries(text):
    return {line.strip().split(" (compatibility", 1)[0]
            for line in text.splitlines()[1:] if line.strip()}


def symbols(text):
    return {line.split()[-1] for line in text.splitlines()
            if line.strip() and not line.endswith(":")}


def require_closure(dependencies, install_name, defined, undefined, exported, commands):
    if install_name != INSTALL_NAME:
        raise ValueError(f"nonrelocatable Unixlib install name: {install_name}")
    if dependencies != SYSTEM | {INSTALL_NAME}:
        raise ValueError(f"unexpected/missing dependency closure: {sorted(dependencies)}")
    if "LC_RPATH" in commands or "LC_DYLD_ENVIRONMENT" in commands:
        raise ValueError("Unixlib must not rely on loader search paths or dyld environment")
    if not CLIENTS <= defined or CLIENTS & undefined:
        raise ValueError("all five real client functions must be statically defined")
    if exported != EXPORTS:
        raise ValueError(f"unexpected Unixlib exports: {sorted(exported)}")


def inspect(path):
    require_closure(
        libraries(output("otool", "-L", str(path))),
        output("otool", "-D", str(path)).splitlines()[1].strip(),
        symbols(output("nm", "-U", str(path))),
        symbols(output("nm", "-u", str(path))),
        symbols(output("nm", "-gU", str(path))),
        output("otool", "-l", str(path)),
    )


def main(root, out):
    unix = out / "lib/wine/x86_64-unix/wvb_autoconfig.so"
    inspect(unix)
    relocated = out / "relocated-candidate"
    if relocated.is_symlink():
        raise ValueError("relocation directory must not be a symlink")
    relocated.mkdir(exist_ok=True)
    for relative in (
        "lib/wine/x86_64-windows/wvb_autoconfig.dll",
        "lib/wine/x86_64-windows/libwvb_autoconfig.dll.a",
        "lib/wine/x86_64-unix/wvb_autoconfig.so",
        "scalar_call_probe.exe",
        "loader_probe.exe",
    ):
        source = out / relative
        destination = relocated / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError(f"relocation destination must not be a symlink: {relative}")
        if not destination.exists():
            with source.open("rb") as stream, destination.open("xb") as target:
                shutil.copyfileobj(stream, target)
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(destination.read_bytes()).digest():
            raise ValueError(f"relocation changed bytes: {relative}")
    moved_unix = relocated / "lib/wine/x86_64-unix/wvb_autoconfig.so"
    inspect(moved_unix)
    linked = moved_unix.with_name("relocation_link_check.dylib")
    output(
        "clang", "-arch", "x86_64", "-std=c17", "-Wall", "-Wextra", "-Werror",
        "-dynamiclib", "-I", str(root / "native/wine-unixlib/include"),
        "-I", str(root / "native/include"), "-I", str(root / "native/macos-keychain/include"),
        str(root / "native/wine-unixlib/tests/client_relocation_link.c"),
        str(moved_unix), "-Wl,-install_name,@loader_path/relocation_link_check.dylib",
        "-o", str(linked),
    )
    if not EXPORTS <= symbols(output("nm", "-u", str(linked))):
        raise ValueError("relocated native link did not import the actual Unix-call exports")
    if libraries(output("otool", "-L", str(linked))) != {
        "@loader_path/relocation_link_check.dylib", INSTALL_NAME, "/usr/lib/libSystem.B.dylib",
    }:
        raise ValueError("relocated native link retained a build-directory dependency")
    output(sys.executable, str(root / "native/wine-unixlib/tests/client_import_test.py"),
           str(root), str(relocated),
           str(relocated / "lib/wine/x86_64-windows/libwvb_autoconfig.dll.a"))
    print("Real static Rust closure and relocated Mach-O/PE links passed; no runtime load performed")


class ClosureTests(unittest.TestCase):
    def test_source_bound_sdk_requires_explicit_identity_and_tools(self):
        self.check_source_guard({}, "requires WVB_WINE_SOURCE_COMMIT")

    def test_wrong_source_commit_stops_before_build(self):
        self.check_source_guard(
            {"WVB_WINE_SOURCE_COMMIT": "0" * 40,
             "WVB_WINEGCC": "/not-executed/winegcc",
             "WVB_WINEBUILD": "/not-executed/winebuild"},
            "not the exact clean commit",
        )

    def check_source_guard(self, settings, expected):
        root = Path(__file__).resolve().parents[3]
        out = root / "out/source-bound-guard-must-not-be-created"
        self.assertFalse(out.exists())
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("WVB_")}
        env.update(WVB_BUILD_OUT=str(out), WVB_WINE_SOURCE=str(root))
        env.update(settings)
        result = subprocess.run(
            ["sh", str(root / "native/wine-unixlib/build-and-test.sh")],
            env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertFalse(out.exists())

    def check(self, **changes):
        values = dict(dependencies=SYSTEM | {INSTALL_NAME}, install_name=INSTALL_NAME,
                      defined=CLIENTS, undefined=set(), exported=EXPORTS, commands="")
        values.update(changes)
        return require_closure(**values)

    def test_system_only_static_closure(self):
        self.check()

    def test_absolute_self_install_name_rejected(self):
        with self.assertRaisesRegex(ValueError, "install name"):
            self.check(install_name="/checkout/out/wvb_autoconfig.so")

    def test_absolute_host_dylib_rejected(self):
        with self.assertRaisesRegex(ValueError, "dependency closure"):
            self.check(dependencies=SYSTEM | {INSTALL_NAME, "/checkout/target/libwvb_client_ffi.dylib"})

    def test_relative_extra_client_dylib_rejected(self):
        with self.assertRaisesRegex(ValueError, "dependency closure"):
            self.check(dependencies=SYSTEM | {INSTALL_NAME, "@loader_path/libwvb_client_ffi.dylib"})

    def test_missing_system_dependency_rejected(self):
        with self.assertRaisesRegex(ValueError, "dependency closure"):
            self.check(dependencies=(SYSTEM | {INSTALL_NAME}) - {"/usr/lib/libiconv.2.dylib"})

    def test_missing_static_function_rejected(self):
        for name in CLIENTS:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "statically defined"):
                self.check(defined=CLIENTS - {name})

    def test_undefined_client_rejected(self):
        with self.assertRaisesRegex(ValueError, "statically defined"):
            self.check(undefined={"_wvb_client_call_ex"})

    def test_rust_exports_rejected(self):
        with self.assertRaisesRegex(ValueError, "exports"):
            self.check(exported=EXPORTS | {"_wvb_client_call_ex"})

    def test_search_path_dependency_rejected(self):
        for commands in ("cmd LC_RPATH", "cmd LC_DYLD_ENVIRONMENT"):
            with self.subTest(commands=commands), self.assertRaisesRegex(ValueError, "search paths"):
                self.check(commands=commands)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    else:
        main(Path(sys.argv[1]), Path(sys.argv[2]))
