#!/usr/bin/env python3
"""Plan, or explicitly run, the separately authorized isolated A08 loader probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import time
from typing import BinaryIO

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "out/runtime-test-a08-20261024"
EVIDENCE = REPO / "out/runtime-test-a08-20261024-evidence"
PREFIX = ROOT / "bottle"
CX = Path("/Applications/CrossOver.app/Contents/SharedSupport/CrossOver")
ENGINE = CX / "lib/wine/x86_64-unix/wine"
SERVER = CX / "bin/wineserver"
INPUTS = {
    REPO / "out/wine-unixlib/loader_probe.exe":
        "a9e6932200fc9cd6c14158f939371d7b27f8bb54ab68a960b417fa36cc59c252",
    REPO / "out/wine-unixlib/lib/wine/x86_64-windows/wvb_autoconfig.dll":
        "c2e6f49b84523404479458a09f3ec397835f97616bd5665de7766fb112188a94",
    REPO / "out/wine-unixlib/lib/wine/x86_64-unix/wvb_autoconfig.so":
        "0157c9c8b4280358664bd785ce6f4b6b61e6cac5d155796f54a94df428b69cb1",
    ENGINE: "b5edb0444b5b25ba0aa5091be1cba11680130895c338cc8044101bce98802a63",
    SERVER: "f9c4ed146c7d6dfc94334255907d4e0658218585085ca2107a5181b4deb474fc",
    CX / "lib/wine/x86_64-unix/ntdll.so":
        "ab32585d767ae631154235861a2e0e8ea61bd09267a2dd341a439e3e8ed071fc",
}
BUILTIN_TRACE = re.compile(
    r'^[^\r\n]*trace:loaddll:[^ :]+\s+Loaded (?:L)?"'
    r'[^"\r\n]*[\\/]wvb_autoconfig\.dll" at (?:0x)?[0-9a-f]+: builtin[ \t]*$',
    re.IGNORECASE | re.MULTILINE,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_inputs() -> None:
    for path, expected in INPUTS.items():
        if digest(path) != expected:
            raise RuntimeError(f"input hash mismatch: {path}")


def environment() -> dict[str, str]:
    return {
        "HOME": str(ROOT / "home"),
        "TMPDIR": str(ROOT / "tmp"),
        "XDG_CACHE_HOME": str(ROOT / "home/.cache"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "WINEPREFIX": str(PREFIX),
        "WINEARCH": "win64",
        "WINESERVER": str(SERVER),
        "WINELOADER": str(ENGINE),
        "WINEDLLPATH": f"{ROOT}/pair/lib/wine:{CX}/lib/wine",
        "WINEDLLOVERRIDES": "wvb_autoconfig=b;winemenubuilder.exe,mscoree,mshtml=",
        "WINEDEBUG": "+timestamp,+pid,+loaddll,+module",
    }


def identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError(f"not an owned directory: {path}")
    return info.st_dev, info.st_ino


def stop_owned(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def ready_line(process: subprocess.Popen[bytes], stream: BinaryIO) -> bytes:
    deadline = time.monotonic() + 30
    data = b""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, min(1, deadline - time.monotonic()))):
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            stream.write(chunk)
            stream.flush()
            data += chunk
            if len(data) > 1_048_576:
                raise RuntimeError("caller stdout bound exceeded")
            if b"a08-loader=loaded export=present " in data:
                return data
    raise RuntimeError("caller did not report successful load before its deadline")


def execute() -> int:
    report: dict = {
        "scope": "synthetic-loader-only-not-generated-proxy-or-app",
        "osConfinement": False,
        "runtimeAcceptance": False,
        "inputSha256": {str(path): value for path, value in INPUTS.items()},
        "environment": environment(),
    }
    caller = server = None
    owned_evidence = prefix_identity = server_identity = None
    owned_directories: dict[Path, tuple[int, int]] = {}
    pending_directory = None
    server_dir = None
    handles = []
    code = 1

    def create_directory(path: Path) -> None:
        nonlocal pending_directory
        path.mkdir(mode=0o700)
        pending_directory = path
        owned_directories[path] = identity(path)
        pending_directory = None

    try:
        verify_inputs()
        for path in (ROOT, EVIDENCE):
            if os.path.lexists(path):
                raise RuntimeError(f"refusing existing path: {path}")
        EVIDENCE.mkdir(mode=0o700)
        owned_evidence = identity(EVIDENCE)
        create_directory(ROOT)
        for relative in (
            "bottle", "home", "tmp", "pair", "pair/lib", "pair/lib/wine",
            "pair/lib/wine/x86_64-windows",
            "pair/lib/wine/x86_64-unix",
        ):
            create_directory(ROOT / relative)
        prefix_identity = owned_directories[PREFIX]
        for source in list(INPUTS)[:3]:
            destination = ROOT / (
                "loader_probe.exe" if source.name == "loader_probe.exe"
                else f"pair/lib/wine/{source.parent.name}/{source.name}"
            )
            shutil.copyfile(source, destination)
            if digest(destination) != INPUTS[source]:
                raise RuntimeError(f"staged hash mismatch: {destination}")
        dev, ino = prefix_identity
        server_dir = Path(f"/tmp/.wine-{os.getuid()}/server-{dev:x}-{ino:x}")
        if os.path.lexists(server_dir):
            raise RuntimeError("refusing existing prefix-specific server endpoint")
        report.update(prefixIdentity=prefix_identity, serverDirectory=str(server_dir))
        env = environment()
        server_log = (EVIDENCE / "server.log").open("xb")
        wine_log = (EVIDENCE / "wine.stderr").open("xb")
        handles.extend((server_log, wine_log))
        server = subprocess.Popen(
            [str(SERVER), "--foreground", "--persistent"], env=env, cwd=ROOT,
            stdout=server_log, stderr=server_log, start_new_session=True,
        )
        report["serverPid"] = server.pid
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise RuntimeError("owned foreground wineserver exited before readiness")
            if server_dir.exists():
                server_identity = identity(server_dir)
                socket = (server_dir / "socket").lstat() if (server_dir / "socket").exists() else None
                if socket and stat.S_ISSOCK(socket.st_mode) and socket.st_uid == os.getuid():
                    break
            time.sleep(0.05)
        else:
            raise RuntimeError("owned wineserver socket did not become ready")
        caller_log = (EVIDENCE / "caller.stdout").open("xb")
        handles.append(caller_log)
        caller = subprocess.Popen(
            [str(ENGINE), str(ROOT / "loader_probe.exe")], env=env, cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=wine_log,
            start_new_session=True,
        )
        report["callerHostPid"] = caller.pid
        output = ready_line(caller, caller_log)
        if caller.poll() is not None:
            raise RuntimeError("caller exited before mapping observation")
        process = subprocess.run(
            ["/bin/ps", "-p", str(caller.pid), "-o", "pid=", "-o", "lstart=", "-o", "comm="],
            check=True, capture_output=True, timeout=3,
        )
        (EVIDENCE / "caller.identity").write_bytes(process.stdout)
        mapping = subprocess.run(
            ["/usr/bin/vmmap", "-w", str(caller.pid)],
            check=True, capture_output=True, timeout=5,
        )
        if caller.poll() is not None:
            raise RuntimeError("caller exited during mapping observation")
        (EVIDENCE / "caller.vmmap").write_bytes(mapping.stdout)
        unixlib = ROOT / "pair/lib/wine/x86_64-unix/wvb_autoconfig.so"
        if str(unixlib.resolve()).encode() not in mapping.stdout:
            raise RuntimeError("exact staged Unixlib absent from owned caller mapping")
        trace = (EVIDENCE / "wine.stderr").read_text(encoding="utf-8")
        match = BUILTIN_TRACE.search(trace)
        if not match:
            raise RuntimeError("required wvb_autoconfig builtin trace predicate not observed")
        report["builtinTraceLine"] = match.group()
        tail, _ = caller.communicate(timeout=15)
        caller_log.write(tail)
        caller_log.flush()
        if caller.returncode != 0 or b"a08-loader=unloaded" not in output + tail:
            raise RuntimeError("caller did not complete successful unload")
        verify_inputs()
        for path in (ROOT / "loader_probe.exe", unixlib, ROOT / "pair/lib/wine/x86_64-windows/wvb_autoconfig.dll"):
            source = next(candidate for candidate in list(INPUTS)[:3] if candidate.name == path.name)
            if digest(path) != INPUTS[source]:
                raise RuntimeError(f"staged file changed: {path}")
        report["loaderOnlyEvidence"] = "observed"
        code = 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(f"a08-loader-probe failed: {error}", flush=True)
    finally:
        try:
            errors = []
            for process in (caller, server):
                try:
                    stop_owned(process)
                except (OSError, subprocess.SubprocessError) as error:
                    errors.append(str(error))
            if caller and caller.stdout:
                caller.stdout.close()
            for handle in handles:
                handle.close()
            if errors:
                raise RuntimeError("owned process shutdown incomplete: " + "; ".join(errors))
            if pending_directory is not None:
                raise RuntimeError(f"created directory identity unknown; cleanup stopped: {pending_directory}")
            if owned_directories:
                for path, expected in owned_directories.items():
                    if identity(path) != expected:
                        raise RuntimeError(f"owned directory identity changed; cleanup stopped: {path}")
                if server is not None or caller is not None:
                    if digest(SERVER) != INPUTS[SERVER]:
                        raise RuntimeError("server binary changed; cleanup execution stopped")
                    subprocess.run(
                        [str(SERVER), "--wait"], env=environment(), cwd=ROOT,
                        check=True, timeout=5, stdout=subprocess.DEVNULL,
                    )
                for process in (caller, server):
                    if process is None:
                        continue
                    group = subprocess.run(
                        ["/bin/ps", "-g", str(process.pid), "-o", "pid="],
                        capture_output=True, timeout=3,
                    )
                    if group.returncode not in (0, 1) or group.stderr or group.stdout.strip():
                        raise RuntimeError("owned process-group absence not verified")
                report["capturedProcessGroupsAbsent"] = True
                if server_dir and os.path.lexists(server_dir):
                    if server_identity is None or identity(server_dir) != server_identity:
                        raise RuntimeError("server identity unknown/changed; cleanup stopped")
                    for path in server_dir.iterdir():
                        info = path.lstat()
                        if path.name not in ("lock", "socket") or info.st_uid != os.getuid() or not (
                            stat.S_ISREG(info.st_mode) or stat.S_ISSOCK(info.st_mode)
                        ):
                            raise RuntimeError("unexpected server artifact; cleanup stopped")
                        path.unlink()
                    server_dir.rmdir()
                shutil.rmtree(ROOT)
                report["ownedRootRestoredAbsent"] = not os.path.lexists(ROOT)
                report["prefixServerAbsent"] = not (server_dir and os.path.lexists(server_dir))
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            report["cleanupError"] = str(error)
            code = 1
            print(f"a08-loader-probe cleanup incomplete: {error}", flush=True)
        if owned_evidence is not None:
            if identity(EVIDENCE) != owned_evidence:
                raise RuntimeError("evidence directory identity changed; report write stopped")
            (EVIDENCE / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="requires separate target/operation/rollback approval")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({
            "execute": False, "root": str(ROOT), "evidence": str(EVIDENCE),
            "inputs": {str(path): value for path, value in INPUTS.items()},
            "environment": environment(),
            "caller": [str(ENGINE), str(ROOT / "loader_probe.exe")],
            "server": [str(SERVER), "--foreground", "--persistent"],
        }, indent=2))
        return 0
    return execute()


if __name__ == "__main__":
    raise SystemExit(main())
