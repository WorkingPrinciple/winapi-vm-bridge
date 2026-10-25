#!/usr/bin/env python3
"""Run one product call against an already-started, explicitly configured guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run_call(wvb: Path, config: Path, request: Path, response: Path,
             expected_u32: int | None = None) -> dict:
    if response.exists():
        raise ValueError("response already exists; never reuse a previous result")
    value = json.loads(config.read_text(encoding="utf-8"))
    budget = (value["connect_timeout_ms"] + value["call_timeout_ms"]) / 1000 + 10
    if not 0 < budget <= 1210:
        raise ValueError("invalid finite call budget")
    command = [str(wvb), "call", "--config", str(config),
               "--request", str(request), "--response", str(response)]
    try:
        completed = subprocess.run(command, check=False, capture_output=True,
                                   text=True, timeout=budget)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("host call observation timed out; guest completion "
                           "unknown; no retry or guest signal") from error
    if completed.returncode != 0:
        raise RuntimeError(f"wvb call failed host_exit={completed.returncode}: "
                           f"{completed.stderr.strip()}; no retry")
    result = json.loads(completed.stdout)
    body = response.read_bytes()
    if (result.get("event") != "result" or result.get("dispatch_status") != 0
            or result.get("response_bytes") != len(body)):
        raise ValueError("product result framing mismatch")
    if expected_u32 is not None:
        if len(body) != 4 or int.from_bytes(body, "little") != expected_u32:
            raise ValueError("returned u32 does not match independently observed guest value")
        result["observed_u32"] = expected_u32
    return result


def reject_crossover(paths) -> None:
    if any("crossover" in str(path).casefold() for path in paths):
        raise ValueError("CrossOver paths are not permitted for active acceptance")


def run_proxy_call(wine: Path, caller: Path, proxy: Path, config: Path,
                   response: Path, trace: Path, expected_u32: int,
                   wine_sha256: str, environment: dict[str, str] | None = None,
                   diagnostics: Path | None = None) -> dict:
    """Call a real generated PE export through an explicitly prepared Wine prefix."""
    environment = os.environ if environment is None else environment
    selected_paths = [str(path) for path in (wine, wine.resolve(), caller, proxy)]
    selected_paths += list(environment.values())
    reject_crossover(selected_paths)
    if hashlib.sha256(wine.read_bytes()).hexdigest() != wine_sha256:
        raise ValueError("Wine engine hash mismatch; no call sent")
    prefix = environment.get("WINEPREFIX")
    initialized_prefix = prefix and (
        (Path(prefix) / "system.reg").is_file()
        or ((Path(prefix) / ".update-timestamp").is_file()
            and (Path(prefix) / "drive_c/windows/system32").is_dir()))
    if (not initialized_prefix
            or not environment.get("WINEDLLPATH")
            or "WHINY_WINE_BOOTSTRAP" in environment):
        raise ValueError("prepare an explicit Wine prefix/builtin path; automatic bootstrap is forbidden")
    if not 0 < expected_u32 <= 0xffffffff:
        raise ValueError("an independently observed guest PID is required")
    if response.exists() or trace.exists():
        raise ValueError("response or trace already exists; never reuse a previous result")
    value = json.loads(config.read_text(encoding="utf-8"))
    key = Path(value["private_key_path"])
    if hashlib.sha256(Path(value["contract_path"]).read_bytes()).digest() != bytes(value["contract_sha256"]):
        raise ValueError("contract hash mismatch; no call sent")
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077:
        raise ValueError("private key must be a private regular file")
    if value["connect_timeout_ms"] != 5000 or value["call_timeout_ms"] != 5000:
        raise ValueError("PID proxy caller requires explicit 5000ms connect/call budgets")

    def windows(path: Path) -> str:
        return "Z:" + str(path.resolve()).replace("/", "\\")

    proxy_hash = hashlib.sha256(proxy.read_bytes()).hexdigest()
    command = [str(wine), str(caller.resolve()), windows(proxy), windows(key),
               value["address"], bytes(value["broker_public_key"]).hex(),
               bytes(value["actor_id"]).hex(), bytes(value["client_instance"]).hex(),
               bytes(value["build_fingerprint"]).hex(), str(expected_u32),
               windows(trace), proxy_hash]
    descriptor = os.open(response, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        try:
            completed = subprocess.run(command, check=False, capture_output=True,
                                       text=True, timeout=60, env=environment)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("proxy call observation timed out; guest completion unknown; no retry") from error
        if diagnostics is not None:
            with diagnostics.open("x", encoding="utf-8") as log:
                log.write(completed.stderr)
        if completed.returncode:
            raise RuntimeError(f"proxy call failed host_exit={completed.returncode}: "
                               f"{completed.stderr.strip()}; no retry")
        match = re.fullmatch(r"pid-proxy result=(\d+) expected=(\d+) caller_pid=(\d+)\r?\n",
                             completed.stdout)
        if not match or int(match[1]) != expected_u32 or int(match[2]) != expected_u32:
            raise ValueError("generated proxy did not report the independently observed guest PID")
        if not trace.is_file():
            raise ValueError("generated proxy returned without its call trace")
        if trace.stat().st_size > 1_048_576:
            raise ValueError("generated proxy trace exceeds bound")
        rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
        if (len(rows) != 4
                or any(not isinstance(row, dict) for row in rows)
                or [row.get("kind") for row in rows] != ["run_start", "entry", "return", "run_end"]
                or any(row.get("sequence") != index or row.get("route") != "remote"
                       or row.get("proxy_artifact_sha256") != proxy_hash
                       or row.get("contract_sha256") != bytes(value["contract_sha256"]).hex()
                       or row.get("process_id") != int(match[3])
                       for index, row in enumerate(rows))
                or rows[1].get("target") != "kernel32.dll!GetCurrentProcessId"
                or rows[2].get("target") != rows[1].get("target")
                or not rows[1].get("call_id") or rows[1].get("call_id") != rows[2].get("call_id")
                or rows[2].get("status") != "ok" or rows[3].get("complete") is not True):
            raise ValueError("generated proxy trace does not prove one completed remote call")
        observed = int(match[1])
        try:
            output.write(observed.to_bytes(4, "little"))
            output.flush()
        except OSError as error:
            raise RuntimeError(f"proxy call returned but result write failed: {error}; no retry") from error
    return {"event": "result", "dispatch_status": 0, "response_bytes": 4,
            "observed_u32": observed, "caller_windows_pid": int(match[3]),
            "route": "generated-proxy", "proxy_sha256": proxy_hash,
            "wine_sha256": wine_sha256}


def run_pid_demo(wine: Path, wine_sha256: str, server_sha256: str,
                 caller: Path, proxy: Path, builtin_root: Path, config: Path,
                 runtime_root: Path, expected_u32: int) -> dict:
    """Explicitly prepare one new private host prefix, call once, and stop its server."""
    if not 0 < expected_u32 <= 0xffffffff:
        raise ValueError("an independently observed guest PID is required")
    wine = wine.absolute()
    server = wine.parent / "wineserver"
    sources = {
        "proxy_call.exe": caller,
        "proxy.dll": proxy,
        "pair/x86_64-windows/wvb_autoconfig.dll":
            builtin_root / "x86_64-windows/wvb_autoconfig.dll",
        "pair/x86_64-unix/wvb_autoconfig.so":
            builtin_root / "x86_64-unix/wvb_autoconfig.so",
    }
    reject_crossover([wine, wine.resolve(), server, server.resolve(), runtime_root,
                      *(path.resolve() for path in sources.values())])
    for executable, expected in ((wine, wine_sha256), (server, server_sha256)):
        if hashlib.sha256(executable.read_bytes()).hexdigest() != expected:
            raise ValueError(f"runtime hash mismatch: {executable}; no call sent")
    runtime_root = runtime_root.absolute()
    runtime_root.mkdir(mode=0o700)
    for relative in ("home", "tmp", "bottle", "pair/x86_64-windows", "pair/x86_64-unix"):
        (runtime_root / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    pins = {}
    for relative, source in sources.items():
        pin = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = runtime_root / relative
        shutil.copyfile(source, destination)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != pin:
            raise RuntimeError(f"staged file hash mismatch: {relative}; no call sent")
        pins[relative] = {"source": str(source.resolve()), "sha256": pin}
    environment = {
        "HOME": str(runtime_root / "home"), "TMPDIR": str(runtime_root / "tmp") + "/",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C",
        "WINEPREFIX": str(runtime_root / "bottle"), "WINEARCH": "win64",
        "WINESERVER": str(server), "WINELOADER": str(wine),
        "WINEDLLPATH": f"{runtime_root}/pair:{wine.parent.parent}/lib/wine",
        "WINEDLLOVERRIDES": "wvb_autoconfig=b;winemenubuilder.exe,mscoree,mshtml=",
        "WINEDEBUG": "+timestamp,+pid,+loaddll,trace-module",
    }
    with (runtime_root / "inputs.json").open("x", encoding="utf-8") as record:
        json.dump({"wine": str(wine), "wine_sha256": wine_sha256,
                   "wineserver_sha256": server_sha256, "inputs": pins,
                   "environment": environment}, record, indent=2)
    with (runtime_root / "server.log").open("xb") as server_log, \
            (runtime_root / "warm.log").open("xb") as warm_log:
        process = subprocess.Popen([str(server), "--foreground", "--persistent=2"],
                                   env=environment, cwd=runtime_root, stdin=subprocess.DEVNULL,
                                   stdout=server_log, stderr=server_log, start_new_session=True)
        initialized = False
        try:
            warm = subprocess.run([str(wine), "wineboot.exe", "--init"],
                                  env=environment, cwd=runtime_root, stdin=subprocess.DEVNULL,
                                  stdout=warm_log, stderr=warm_log, timeout=60, check=False)
            if warm.returncode or process.poll() is not None:
                raise RuntimeError("owned prefix initialization failed; no guest call attempted")
            initialized = True
            result = run_proxy_call(wine, runtime_root / "proxy_call.exe",
                                    runtime_root / "proxy.dll", config,
                                    runtime_root / "response.bin", runtime_root / "trace.jsonl",
                                    expected_u32, wine_sha256, environment,
                                    runtime_root / "caller.stderr")
            with (runtime_root / "result.json").open("x", encoding="utf-8") as record:
                json.dump(result, record, sort_keys=True)
            return result
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("owned prefix initialization timed out; no guest call attempted") from error
        finally:
            with (runtime_root / "shutdown.log").open("xb") as log:
                try:
                    if initialized:
                        shutdown = subprocess.run([str(wine), "wineboot.exe", "--end-session",
                                                   "--force", "--kill", "--shutdown"],
                                                  env=environment, cwd=runtime_root,
                                                  stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                  timeout=15, check=False)
                        if shutdown.returncode:
                            raise RuntimeError("owned prefix shutdown failed; evidence retained; no replay")
                except subprocess.TimeoutExpired as error:
                    raise RuntimeError("owned prefix shutdown timed out; evidence retained; no replay") from error
                finally:
                    if process.poll() is None:
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=5)
                            raise RuntimeError("owned Wine server did not drain; prefix quiescence unknown; evidence retained; no replay")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    executable = parser.add_mutually_exclusive_group(required=True)
    executable.add_argument("--wvb", type=Path)
    executable.add_argument("--proxy-caller", type=Path)
    parser.add_argument("--wine", type=Path)
    parser.add_argument("--wine-sha256")
    parser.add_argument("--demo-pid", action="store_true",
                        help="Explicitly create a new private Wine prefix and run the real PID proxy once")
    parser.add_argument("--wineserver-sha256")
    parser.add_argument("--builtin-root", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--proxy", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--response", type=Path)
    parser.add_argument("--expected-u32", type=int)
    args = parser.parse_args()
    if args.demo_pid:
        if (not all((args.proxy_caller, args.wine, args.wine_sha256, args.wineserver_sha256,
                     args.proxy, args.builtin_root, args.runtime_root, args.expected_u32))
                or any((args.trace, args.response, args.request))):
            parser.error("demo requires proxy-caller/wine/runtime hashes/proxy/builtin-root/runtime-root/expected-u32; output paths are derived")
        result = run_pid_demo(args.wine, args.wine_sha256, args.wineserver_sha256,
                              args.proxy_caller, args.proxy, args.builtin_root, args.config,
                              args.runtime_root, args.expected_u32)
    elif args.proxy_caller:
        if not all((args.wine, args.wine_sha256, args.proxy, args.trace, args.response, args.expected_u32)):
            parser.error("proxy mode requires --wine, --wine-sha256, --proxy, --trace, --response and --expected-u32")
        result = run_proxy_call(args.wine, args.proxy_caller, args.proxy, args.config,
                                args.response, args.trace, args.expected_u32, args.wine_sha256)
    else:
        if args.request is None or args.response is None or any((args.wine, args.wine_sha256, args.proxy, args.trace)):
            parser.error("product mode requires --request and no proxy-mode arguments")
        result = run_call(args.wvb, args.config, args.request, args.response,
                           args.expected_u32)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"run_generated_call: {error}", file=sys.stderr)
        raise SystemExit(2)
