#!/usr/bin/env python3
"""Run one product call against an already-started, explicitly configured guest."""

import argparse
from collections.abc import Callable
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


def proxy_inputs(wine: Path, caller: Path, proxy: Path, config: Path,
                 response: Path, trace: Path, wine_sha256: str,
                 environment: dict[str, str], call_timeout_ms: int) -> tuple[dict, Path, str]:
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
    if response.exists() or trace.exists():
        raise ValueError("response or trace already exists; never reuse a previous result")
    value = json.loads(config.read_text(encoding="utf-8"))
    key = Path(value["private_key_path"])
    if hashlib.sha256(Path(value["contract_path"]).read_bytes()).digest() != bytes(value["contract_sha256"]):
        raise ValueError("contract hash mismatch; no call sent")
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077:
        raise ValueError("private key must be a private regular file")
    if value["connect_timeout_ms"] != 5000 or value["call_timeout_ms"] != call_timeout_ms:
        raise ValueError(f"proxy caller requires explicit 5000/{call_timeout_ms}ms connect/call budgets")
    return value, key, hashlib.sha256(proxy.read_bytes()).hexdigest()


def windows(path: Path) -> str:
    return "Z:" + str(path.resolve()).replace("/", "\\")


def run_proxy_call(wine: Path, caller: Path, proxy: Path, config: Path,
                   response: Path, trace: Path, expected_u32: int,
                   wine_sha256: str, environment: dict[str, str] | None = None,
                   diagnostics: Path | None = None) -> dict:
    """Call a real generated PE export through an explicitly prepared Wine prefix."""
    environment = os.environ if environment is None else environment
    value, key, proxy_hash = proxy_inputs(
        wine, caller, proxy, config, response, trace, wine_sha256, environment, 5000)
    if not 0 < expected_u32 <= 0xffffffff:
        raise ValueError("an independently observed guest PID is required")
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


def checked_trace_validator(whiny: Path | None, expected_sha256: str | None) -> Path:
    if whiny is None or expected_sha256 is None:
        raise ValueError("COM trace requires an explicit hash-pinned Whiny trace validator")
    if hashlib.sha256(whiny.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("COM trace validator hash mismatch; no call sent")
    return whiny.absolute()


def validate_com_recording(whiny: Path, trace: Path, contract_hash: str, proxy_hash: str) -> str:
    observation = trace.with_suffix(".validation-observed.json")
    report = trace.with_suffix(".validation.json")
    command = [str(whiny), "trace", str(trace)]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value
        with observation.open("x", encoding="utf-8") as stream:
            json.dump({"command": command, "timed_out": True,
                       "stdout": text(error.stdout), "stderr": text(error.stderr)}, stream)
        raise RuntimeError("COM trace validator timed out after the calls; evidence retained; no retry") from error
    with observation.open("x", encoding="utf-8") as stream:
        json.dump({"command": [str(whiny), "trace", str(trace)], "exit_code": completed.returncode,
                   "stdout": completed.stdout, "stderr": completed.stderr}, stream)
    if completed.returncode:
        raise ValueError(f"COM trace rejected by whiny trace: {completed.stderr.strip()}; no retry")
    summary = json.loads(completed.stdout)
    if (not isinstance(summary, dict) or summary.get("complete") is not True
            or any(type(summary.get(field)) is not int for field in ("calls", "events", "dropped_events"))
            or summary.get("calls") != 5 or summary.get("events") != 12
            or summary.get("dropped_events") != 0 or summary.get("route") != "remote"
            or summary.get("contract_sha256") != contract_hash
            or summary.get("proxy_artifact_sha256") != proxy_hash):
        raise ValueError("COM trace validator did not prove this complete five-call recording")
    with report.open("x", encoding="utf-8") as stream:
        stream.write(completed.stdout)
    return hashlib.sha256(report.read_bytes()).hexdigest()


def run_com_proxy(wine: Path, caller: Path, proxy: Path, config: Path,
                  response: Path, trace: Path, wine_sha256: str,
                  environment: dict[str, str], diagnostics: Path,
                  whiny: Path | None = None, whiny_sha256: str | None = None) -> dict:
    """Run the owned COM fixture caller once; native oracle comparison is separate."""
    value, key, proxy_hash = proxy_inputs(
        wine, caller, proxy, config, response, trace, wine_sha256, environment, 10000)
    if whiny is not None or whiny_sha256 is not None:
        whiny = checked_trace_validator(whiny, whiny_sha256)
        if any(trace.with_suffix(suffix).exists()
               for suffix in (".validation-observed.json", ".validation.json")):
            raise ValueError("COM trace validation evidence already exists; never reuse a run")
    contract = json.loads(Path(value["contract_path"]).read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise ValueError("COM contract must be an object")
    object_slice = contract.get("object_slice", {})
    activation = object_slice.get("activation") if isinstance(object_slice, dict) else None
    iid = object_slice.get("interface_iid") if isinstance(object_slice, dict) else None
    clsid = activation.get("clsid") if isinstance(activation, dict) else None
    target = contract.get("target")
    target_path = target.get("relative_path") if isinstance(target, dict) else None
    if (not isinstance(object_slice, dict) or object_slice.get("abi") != "com-u32-v1"
            or object_slice.get("method_slot") != 3
            or not isinstance(activation, dict) or activation.get("kind") != "com-local-server"
            or not isinstance(target_path, str) or not target_path
            or not isinstance(iid, str) or iid.casefold() != "ba9a4da2-79fe-4b31-8db4-201af0266c12"
            or not isinstance(clsid, str) or clsid.casefold() != "ba9a4da2-79fe-4b31-8db4-201af0266c11"):
        raise ValueError("COM caller requires the owned fixture's exact class/interface contract")
    if diagnostics.exists():
        raise ValueError("diagnostics already exist; never reuse a previous run")
    command = [str(wine), str(caller.resolve()), windows(proxy), windows(key),
               value["address"], bytes(value["broker_public_key"]).hex(),
               bytes(value["actor_id"]).hex(), bytes(value["client_instance"]).hex(),
               bytes(value["build_fingerprint"]).hex(), windows(trace), proxy_hash,
               bytes(value["contract_sha256"]).hex()]
    descriptor = os.open(response, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output, diagnostics.open("x", encoding="utf-8") as log:
        try:
            completed = subprocess.run(command, check=False, capture_output=True,
                                       text=True, timeout=60, env=environment)
        except subprocess.TimeoutExpired as error:
            if error.stdout:
                output.write(error.stdout if isinstance(error.stdout, bytes)
                             else error.stdout.encode("utf-8"))
            log.write("caller observation timed out; guest completion unknown; no retry\n")
            if error.stderr:
                log.write(error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes)
                          else error.stderr)
            raise RuntimeError("COM caller observation timed out; guest completion unknown; no retry") from error
        log.write(completed.stderr)
        output.write(completed.stdout.encode("utf-8"))
        output.flush()
        if completed.returncode:
            raise RuntimeError(f"COM caller failed host_exit={completed.returncode}: "
                               f"{completed.stderr.strip()}; no retry")
        rows = [json.loads(line) for line in completed.stdout.splitlines()]
        if (len(rows) != 4 or any(not isinstance(row, dict) for row in rows)
                or [row.get("event") for row in rows]
                != ["result", "native-error", "release", "control-negatives"]
                or any(type(row.get(field)) is not int for row, fields in zip(rows, (
                    ("activation_hresult", "hresult", "output", "caller_pid"),
                    ("hresult", "output"), ("references", "can_unload_hresult")))
                       for field in fields)
                or rows[0].get("activation_hresult") != 0
                or rows[0].get("hresult") != 0 or rows[0].get("output") != 42
                or type(rows[0].get("caller_pid")) is not int or rows[0]["caller_pid"] <= 0
                or rows[1].get("hresult") != -2147024809 or rows[1].get("output") != 0
                or rows[2].get("references") != 0 or rows[2].get("can_unload_hresult") != 0
                or type(rows[2].get("recording")) is not bool
                or any(rows[3].get(field) is not True for field in (
                    "wrong_epoch", "wrong_generation", "wrong_type", "lease_survived", "closed", "stale"))):
            raise ValueError("COM caller did not prove activation, typed HRESULT/writeback and final release")
        recording = rows[2]["recording"]
        if recording:
            if not trace.is_file() or trace.stat().st_size > 1_048_576:
                raise ValueError("COM caller reported recording without a bounded trace")
            records = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
            if (len(records) < 4 or any(not isinstance(row, dict) for row in records)
                    or records[0].get("kind") != "run_start"
                    or records[-1].get("kind") != "run_end"
                    or records[-1].get("complete") is not True
                    or any(row.get("sequence") != index or row.get("route") != "remote"
                           or row.get("proxy_artifact_sha256") != proxy_hash
                           or row.get("contract_sha256") != bytes(value["contract_sha256"]).hex()
                           or row.get("process_id") != rows[0]["caller_pid"]
                           for index, row in enumerate(records))):
                raise ValueError("COM trace is incomplete or not bound to this generated caller")
            pending = {}
            seen = set()
            returns = []
            for record in records[1:-1]:
                call_id = record.get("call_id")
                target = record.get("target")
                if not isinstance(call_id, str) or not call_id or not isinstance(target, str) or not target:
                    raise ValueError("COM trace lacks a call identity/target")
                if record.get("kind") == "entry" and call_id not in seen:
                    pending[call_id] = target
                    seen.add(call_id)
                elif record.get("kind") == "return" and pending.pop(call_id, None) == target:
                    returns.append((target, record.get("status")))
                    continue
                else:
                    raise ValueError("COM trace has an unmatched or duplicate call")
            if pending:
                raise ValueError("COM trace has calls without returns")
            server_name = target_path.replace("\\", "/").rsplit("/", 1)[-1]
            method = f"{server_name}!{iid}#3"
            if returns != [
                    (f"{server_name}!{clsid}::activate", "ok"),
                    (method, "invalid_input"), (method, "ok"), (method, "call_failed"),
                    (f"{server_name}!{iid}::release", "ok")]:
                raise ValueError("COM trace does not prove the exact activation/method/release outcomes")
            whiny = checked_trace_validator(whiny, whiny_sha256)
            validation_hash = validate_com_recording(
                whiny, trace, bytes(value["contract_sha256"]).hex(), proxy_hash)
        elif trace.exists():
            raise ValueError("COM caller reported no recording but created a trace")
    return {"event": "result", "route": "generated-com-proxy", "supporting_only": True,
            "native_oracle_compared": False, "generated_recording": recording,
            "trace_validated": recording,
            "trace_validation_sha256": validation_hash if recording else None,
            "trace_validator_sha256": whiny_sha256 if recording else None,
            "caller_windows_pid": rows[0]["caller_pid"], "proxy_sha256": proxy_hash,
            "wine_sha256": wine_sha256}


def run_pid_demo(wine: Path, wine_sha256: str, server_sha256: str,
                 caller: Path, proxy: Path, builtin_root: Path, config: Path,
                 runtime_root: Path, expected_u32: int) -> dict:
    if not 0 < expected_u32 <= 0xffffffff:
        raise ValueError("an independently observed guest PID is required")
    return run_isolated_demo(wine, wine_sha256, server_sha256, caller, proxy, builtin_root,
        runtime_root, lambda root, environment: run_proxy_call(
            wine.absolute(), root / "proxy_call.exe", root / "proxy.dll", config,
            root / "response.bin", root / "trace.jsonl", expected_u32, wine_sha256,
            environment, root / "caller.stderr"))


def read_com_oracle(path: Path, expected_sha256: str) -> list[dict]:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("native COM oracle hash mismatch; no generated call sent")
    rows = [json.loads(line) for line in data.decode("utf-8-sig").splitlines()]
    if (len(rows) != 2 or any(not isinstance(row, dict) for row in rows)
            or [row.get("event") for row in rows] != ["oracle", "oracle-error"]
            or any(type(row.get(field)) is not int for row, fields in zip(rows, (
                ("input", "hresult", "output", "caller_pid"), ("hresult", "output")))
                   for field in fields)
            or rows[0].get("input") != 41 or rows[0].get("hresult") != 0
            or rows[0].get("output") != 42 or rows[0].get("caller_pid", 0) <= 0
            or rows[1].get("hresult") != -2147024809 or rows[1].get("output") != 0):
        raise ValueError("native COM oracle does not match the observed OOP fixture baseline")
    return rows


def compare_com_oracle(native: list[dict], generated: Path) -> dict:
    rows = [json.loads(line) for line in generated.read_text(encoding="utf-8").splitlines()]
    if (len(rows) < 2 or any(not isinstance(row, dict) for row in rows)
            or rows[0].get("event") != "result" or rows[1].get("event") != "native-error"):
        raise ValueError("generated COM oracle comparison rows are malformed")
    cells = {}
    for index, label in enumerate(("success", "native-error")):
        for field in ("hresult", "output"):
            original, actual = native[index][field], rows[index].get(field)
            if type(actual) is not int or actual != original:
                raise ValueError(f"COM native parity mismatch: {label}.{field}")
            cells[f"{label}.{field}"] = {"native": original, "generated": actual, "equal": True}
    return cells


def run_com_demo(wine: Path, wine_sha256: str, server_sha256: str,
                 caller: Path, proxy: Path, builtin_root: Path, config: Path,
                 runtime_root: Path, oracle_stdout: Path | None = None,
                 oracle_sha256: str | None = None, whiny: Path | None = None,
                 whiny_sha256: str | None = None) -> dict:
    if (oracle_stdout is None) != (oracle_sha256 is None):
        raise ValueError("native COM oracle path and hash must be supplied together")
    native = read_com_oracle(oracle_stdout, oracle_sha256) if (
        oracle_stdout is not None and oracle_sha256 is not None) else None
    whiny = checked_trace_validator(whiny, whiny_sha256)

    def invoke(root, environment):
        response = root / "response.jsonl"
        result = run_com_proxy(wine.absolute(), root / "proxy_call.exe", root / "proxy.dll", config,
                               response, root / "trace.jsonl", wine_sha256, environment,
                               root / "caller.stderr", whiny, whiny_sha256)
        if result.get("trace_validated") is not True:
            raise ValueError("COM demo requires a schema-valid generated recording")
        if native is not None:
            result["native_oracle_cells"] = compare_com_oracle(native, response)
            result["native_oracle_compared"] = True
            result["native_oracle_stdout_sha256"] = oracle_sha256
            result["native_caller_windows_pid"] = native[0]["caller_pid"]
        return result

    return run_isolated_demo(wine, wine_sha256, server_sha256, caller, proxy, builtin_root,
                             runtime_root, invoke)


def run_isolated_demo(wine: Path, wine_sha256: str, server_sha256: str,
                      caller: Path, proxy: Path, builtin_root: Path,
                      runtime_root: Path,
                      call_once: Callable[[Path, dict[str, str]], dict]) -> dict:
    """Prepare one new private prefix, invoke once and drain only its own server."""
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
            result = call_once(runtime_root, environment)
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
    demo = parser.add_mutually_exclusive_group()
    demo.add_argument("--demo-pid", action="store_true",
                        help="Explicitly create a new private Wine prefix and run the real PID proxy once")
    demo.add_argument("--demo-com", action="store_true",
                      help="Run the owned COM scalar facade once in a new private Calimocho prefix")
    parser.add_argument("--wineserver-sha256")
    parser.add_argument("--builtin-root", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--proxy", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--response", type=Path)
    parser.add_argument("--expected-u32", type=int)
    parser.add_argument("--oracle-stdout", type=Path)
    parser.add_argument("--oracle-sha256")
    parser.add_argument("--whiny", type=Path)
    parser.add_argument("--whiny-sha256")
    args = parser.parse_args()
    if ((args.oracle_stdout is None) != (args.oracle_sha256 is None)
            or (not args.demo_com and (args.oracle_stdout is not None or args.oracle_sha256 is not None))):
        parser.error("oracle stdout/hash are a paired option for --demo-com only")
    if ((args.whiny is None) != (args.whiny_sha256 is None)
            or (not args.demo_com and (args.whiny is not None or args.whiny_sha256 is not None))):
        parser.error("whiny executable/hash are a paired option for --demo-com only")
    if args.demo_pid or args.demo_com:
        if (not all((args.proxy_caller, args.wine, args.wine_sha256, args.wineserver_sha256,
                     args.proxy, args.builtin_root, args.runtime_root))
                or any((args.trace, args.response, args.request))
                or (args.demo_pid and args.expected_u32 is None)
                or (args.demo_com and (args.expected_u32 is not None or args.whiny is None))):
            parser.error("demo requires proxy-caller/wine/runtime hashes/proxy/builtin-root/runtime-root; PID also requires expected-u32; COM requires whiny/whiny-sha256; output paths are derived")
        arguments = (args.wine, args.wine_sha256, args.wineserver_sha256,
                     args.proxy_caller, args.proxy, args.builtin_root, args.config, args.runtime_root)
        result = run_pid_demo(*arguments, args.expected_u32) if args.demo_pid else run_com_demo(
            *arguments, args.oracle_stdout, args.oracle_sha256, args.whiny, args.whiny_sha256)
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
