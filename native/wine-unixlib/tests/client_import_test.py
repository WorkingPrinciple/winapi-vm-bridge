"""Build/inspect only: never execute a PE or load a Bridge/client module."""

from pathlib import Path
import subprocess
import sys

CLIENTS = {
    "wvb_client_configure", "wvb_client_bind_operation", "wvb_client_call",
    "wvb_client_call_ex", "wvb_client_reset", "wvb_client_handle_close",
}


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout


def require_symbols(library):
    text = run("x86_64-w64-mingw32-nm", "-g", str(library))
    defined = {
        line.split()[-1] for line in text.splitlines()
        if len(line.split()) == 3 and line.split()[-2] in ("T", "I")
    }
    needed = CLIENTS | {"__imp_" + name for name in CLIENTS}
    if not needed <= defined:
        raise ValueError(f"missing actual C import thunks: {sorted(needed - defined)}")


def require_imports(pe, expected):
    text = run("x86_64-w64-mingw32-objdump", "-p", str(pe))
    dll = None
    observed = {}
    for line in text.splitlines():
        if line.startswith("The Export Tables"):
            break
        words = line.split()
        if words[:2] == ["DLL", "Name:"]:
            dll = words[2].lower()
            observed[dll] = set()
        elif dll and len(words) >= 3 and words[-1].startswith("wvb_client_"):
            observed[dll].add(words[-1])
    assert observed.get("wvb_autoconfig.dll") == expected, observed
    assert not any(
        name.startswith("wvb_client_")
        for module, names in observed.items() if module != "wvb_autoconfig.dll"
        for name in names
    ), observed


def main():
    root = Path(sys.argv[1])
    out = Path(sys.argv[2])
    library = Path(sys.argv[3])
    command = [
        "x86_64-w64-mingw32-gcc", "-std=c17", "-Wall", "-Wextra", "-Werror",
        "-O2", "-shared", "-static", "-static-libgcc",
        "-Wl,--no-insert-timestamp", "-I", str(root / "native/include"),
        str(root / "native/wine-unixlib/tests/client_import_test.c"),
    ]
    if len(sys.argv) == 5 and sys.argv[4] == "--expect-missing-thunks":
        try:
            require_symbols(library)
        except ValueError:
            pass
        else:
            raise AssertionError("negative archive unexpectedly has client thunks")
        failure = subprocess.run(
            [*command, str(library), "-o", str(out / "missing_thunks_must_not_link.dll")],
            capture_output=True, text=True, timeout=60,
        )
        assert failure.returncode != 0 and "undefined reference" in failure.stderr
        assert any(name in failure.stderr for name in CLIENTS), failure.stderr
        print("Missing-thunk archive rejected by symbol guard AND actual consumer linker")
        return
    require_symbols(library)
    output = out / "client_import_link_check.dll"
    run(*command, str(library), "-o", str(output))
    require_imports(output, CLIENTS)

    # A DLL-name-only archive reproduces the original GNU --out-implib failure.
    definition = out / "missing-client-thunks.def"
    broken = out / "missing-client-thunks.dll.a"
    definition.write_text("LIBRARY wvb_autoconfig.dll\nEXPORTS\n", encoding="ascii")
    run("x86_64-w64-mingw32-dlltool", "-d", str(definition), "-l", str(broken))
    assert run("x86_64-w64-mingw32-dlltool", "-I", str(broken)).strip() == "wvb_autoconfig.dll"
    run(sys.executable, str(Path(__file__)), str(root), str(out), str(broken),
        "--expect-missing-thunks")
    print("All six actual client thunks link and import wvb_autoconfig.dll; missing-thunk regression rejected")


if __name__ == "__main__":
    main()
