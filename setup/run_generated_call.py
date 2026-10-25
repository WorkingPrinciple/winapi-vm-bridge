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


def checked_trace_validator(whiny: Path | None, expected_sha256: str | None,
                            kind: str = "COM") -> Path:
    if whiny is None or expected_sha256 is None:
        raise ValueError(f"{kind} trace requires an explicit hash-pinned Whiny trace validator")
    if hashlib.sha256(whiny.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError(f"{kind} trace validator hash mismatch; no call sent")
    return whiny.absolute()


def validate_object_recording(whiny: Path, trace: Path, contract_hash: str, proxy_hash: str,
                              calls: int, kind: str) -> str:
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
        raise RuntimeError(f"{kind} trace validator timed out after the calls; evidence retained; no retry") from error
    with observation.open("x", encoding="utf-8") as stream:
        json.dump({"command": [str(whiny), "trace", str(trace)], "exit_code": completed.returncode,
                   "stdout": completed.stdout, "stderr": completed.stderr}, stream)
    if completed.returncode:
        raise ValueError(f"{kind} trace rejected by whiny trace: {completed.stderr.strip()}; no retry")
    try:
        summary = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"{kind} trace validator returned invalid JSON; evidence retained; no retry") from error
    if (not isinstance(summary, dict) or summary.get("complete") is not True
            or any(type(summary.get(field)) is not int for field in ("calls", "events", "dropped_events"))
            or summary.get("calls") != calls or summary.get("events") != calls * 2 + 2
            or summary.get("dropped_events") != 0 or summary.get("route") != "remote"
            or summary.get("contract_sha256") != contract_hash
            or summary.get("proxy_artifact_sha256") != proxy_hash):
        raise ValueError(f"{kind} trace validator did not prove this complete {calls}-call recording")
    with report.open("x", encoding="utf-8") as stream:
        stream.write(completed.stdout)
    return hashlib.sha256(report.read_bytes()).hexdigest()


def run_object_proxy(wine: Path, caller: Path, proxy: Path, config: Path,
                  response: Path, trace: Path, wine_sha256: str,
                  environment: dict[str, str], diagnostics: Path,
                  whiny: Path | None = None, whiny_sha256: str | None = None,
                  *, winrt: bool = False) -> dict:
    """Run an owned object fixture caller once; native comparison is separate."""
    kind = "WinRT" if winrt else "COM"
    value, key, proxy_hash = proxy_inputs(
        wine, caller, proxy, config, response, trace, wine_sha256, environment, 10000)
    if whiny is not None or whiny_sha256 is not None:
        whiny = checked_trace_validator(whiny, whiny_sha256, kind)
        if any(trace.with_suffix(suffix).exists()
               for suffix in (".validation-observed.json", ".validation.json")):
            raise ValueError(f"{kind} trace validation evidence already exists; never reuse a run")
    contract = json.loads(Path(value["contract_path"]).read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise ValueError(f"{kind} contract must be an object")
    object_slice = contract.get("object_slice", {})
    activation = object_slice.get("activation") if isinstance(object_slice, dict) else None
    iid = object_slice.get("interface_iid") if isinstance(object_slice, dict) else None
    clsid = activation.get("clsid") if isinstance(activation, dict) else None
    target = contract.get("target")
    target_path = target.get("relative_path") if isinstance(target, dict) else None
    if (not isinstance(object_slice, dict)
            or object_slice.get("abi") != ("winrt-u32-v1" if winrt else "com-u32-v1")
            or object_slice.get("method_slot") != (8 if winrt else 3)
            or not isinstance(activation, dict)
            or activation.get("kind") != ("winrt-factory" if winrt else "com-local-server")
            or not isinstance(target_path, str) or not target_path
            or not isinstance(iid, str) or iid.casefold() != (
                "5f1c7a3e-2b4d-4e6f-8a9b-0c1d2e3f4a52" if winrt
                else "ba9a4da2-79fe-4b31-8db4-201af0266c12")
            or (winrt and (
                activation.get("runtime_class") != "Wvb.Test.WvbScalarRuntimeClass"
                or activation.get("factory_iid") != "5F1C7A3E-2B4D-4E6F-8A9B-0C1D2E3F4A51"
                or object_slice.get("factory_method_slot") != 7))
            or (not winrt and (
                not isinstance(clsid, str)
                or clsid.casefold() != "ba9a4da2-79fe-4b31-8db4-201af0266c11"))):
        raise ValueError(f"{kind} caller requires the owned fixture's exact class/interface contract")
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
            raise RuntimeError(f"{kind} caller observation timed out; guest completion unknown; no retry") from error
        log.write(completed.stderr)
        output.write(completed.stdout.encode("utf-8"))
        output.flush()
        if completed.returncode:
            raise RuntimeError(f"{kind} caller failed host_exit={completed.returncode}: "
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
                or rows[1].get("hresult") != -2147024809
                or rows[1].get("output") != (0xa5a5a5a5 if winrt else 0)
                or rows[2].get("references") != 0 or rows[2].get("can_unload_hresult") != 0
                or type(rows[2].get("recording")) is not bool
                or any(rows[3].get(field) is not True for field in (
                    "wrong_epoch", "wrong_generation", "wrong_type", "lease_survived", "closed", "stale"))):
            raise ValueError(f"{kind} caller did not prove activation, typed HRESULT/writeback and final release")
        if winrt and (
                any(type(rows[0].get(field)) is not int for field in (
                    "create_hresult", "factory_references", "instance_alive_unload_hresult"))
                or rows[0]["create_hresult"] != 0 or rows[0]["factory_references"] != 0
                or rows[0]["instance_alive_unload_hresult"] != 1
                or any(rows[3].get(field) is not True for field in (
                    "role_swapped_close", "factory_closed", "instance_survived"))):
            raise ValueError("WinRT caller did not prove independent factory/instance leases")
        recording = rows[2]["recording"]
        if recording:
            if not trace.is_file() or trace.stat().st_size > 1_048_576:
                raise ValueError(f"{kind} caller reported recording without a bounded trace")
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
                raise ValueError(f"{kind} trace is incomplete or not bound to this generated caller")
            pending = {}
            seen = set()
            returns = []
            for record in records[1:-1]:
                call_id = record.get("call_id")
                target = record.get("target")
                if not isinstance(call_id, str) or not call_id or not isinstance(target, str) or not target:
                    raise ValueError(f"{kind} trace lacks a call identity/target")
                if record.get("kind") == "entry" and call_id not in seen:
                    pending[call_id] = target
                    seen.add(call_id)
                elif record.get("kind") == "return" and pending.pop(call_id, None) == target:
                    returns.append((target, record.get("status")))
                    continue
                else:
                    raise ValueError(f"{kind} trace has an unmatched or duplicate call")
            if pending:
                raise ValueError(f"{kind} trace has calls without returns")
            server_name = target_path.replace("\\", "/").rsplit("/", 1)[-1]
            method = f"{server_name}!{iid}#{8 if winrt else 3}"
            expected = [
                    (f"{server_name}!{clsid}::activate", "ok"),
                    (method, "invalid_input"), (method, "ok"), (method, "call_failed"),
                    (f"{server_name}!{iid}::release", "ok")]
            if winrt:
                factory = activation["factory_iid"]
                expected[:1] = [
                    (f"{server_name}!{activation['runtime_class']}::factory", "ok"),
                    (f"{server_name}!{factory}#7", "ok"),
                    (f"{server_name}!{factory}::release", "ok")]
            if returns != expected:
                raise ValueError(f"{kind} trace does not prove the exact activation/method/release outcomes")
            whiny = checked_trace_validator(whiny, whiny_sha256, kind)
            validation_hash = validate_object_recording(
                whiny, trace, bytes(value["contract_sha256"]).hex(), proxy_hash, len(expected), kind)
        elif trace.exists():
            raise ValueError(f"{kind} caller reported no recording but created a trace")
    return {"event": "result", "route": "generated-winrt-proxy" if winrt else "generated-com-proxy",
            "supporting_only": True,
            "native_oracle_compared": False, "generated_recording": recording,
            "trace_validated": recording,
            "trace_validation_sha256": validation_hash if recording else None,
            "trace_validator_sha256": whiny_sha256 if recording else None,
            "caller_windows_pid": rows[0]["caller_pid"], "proxy_sha256": proxy_hash,
            "wine_sha256": wine_sha256}

run_com_proxy = run_object_proxy


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


def compare_com_oracle(native: list[dict], generated: Path, kind: str = "COM") -> dict:
    rows = [json.loads(line) for line in generated.read_text(encoding="utf-8").splitlines()]
    if (len(rows) < 2 or any(not isinstance(row, dict) for row in rows)
            or rows[0].get("event") != "result" or rows[1].get("event") != "native-error"):
        raise ValueError(f"generated {kind} oracle comparison rows are malformed")
    cells = {}
    for index, label in enumerate(("success", "native-error")):
        for field in ("hresult", "output"):
            original, actual = native[index][field], rows[index].get(field)
            if type(actual) is not int or actual != original:
                raise ValueError(f"{kind} native parity mismatch: {label}.{field}")
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

def read_winrt_oracle(path: Path, expected_sha256: str) -> list[dict]:
    data = path.read_bytes()
    if len(data) > 1_048_576 or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("native WinRT oracle hash/bound mismatch; no generated call sent")
    rows = [json.loads(line) for line in data.decode("utf-8-sig").splitlines()]
    if (len(rows) != 6 or any(not isinstance(row, dict) for row in rows)
            or [row.get("event") for row in rows] != [
                "factory", "module", "create", "module", "oracle", "oracle-error"]
            or any(type(rows[index].get(field)) is not int for index, fields in (
                (0, ("hresult", "caller_pid", "thread")), (2, ("hresult",)),
                (4, ("hresult", "output")), (5, ("hresult", "output"))) for field in fields)
            or rows[0]["hresult"] != 0 or rows[0]["caller_pid"] <= 0 or rows[0]["thread"] <= 0
            or rows[2]["hresult"] != 0
            or rows[4]["hresult"] != 0 or rows[4]["output"] != 42
            or rows[5]["hresult"] != -2147024809 or rows[5]["output"] != 0xa5a5a5a5
            or rows[1].get("role") != "factory" or rows[3].get("role") != "instance"
            or not isinstance(rows[1].get("path"), str)
            or not rows[1]["path"].endswith("\\Wvb.Test.WvbScalarRuntimeClass.dll")
            or rows[3].get("path") != rows[1]["path"]):
        raise ValueError("native WinRT oracle does not prove the owned registration-free baseline")
    return rows


def run_winrt_demo(wine: Path, wine_sha256: str, server_sha256: str,
                   caller: Path, proxy: Path, builtin_root: Path, config: Path,
                   runtime_root: Path, oracle_stdout: Path | None, oracle_sha256: str | None,
                   whiny: Path | None, whiny_sha256: str | None) -> dict:
    if oracle_stdout is None or oracle_sha256 is None:
        raise ValueError("WinRT requires a hash-pinned native oracle before the generated call")
    native = read_winrt_oracle(oracle_stdout, oracle_sha256)
    whiny = checked_trace_validator(whiny, whiny_sha256, "WinRT")

    def invoke(root, environment):
        response = root / "response.jsonl"
        result = run_object_proxy(wine.absolute(), root / "proxy_call.exe", root / "proxy.dll", config,
                                  response, root / "trace.jsonl", wine_sha256, environment,
                                  root / "caller.stderr", whiny, whiny_sha256, winrt=True)
        if result.get("trace_validated") is not True:
            raise ValueError("WinRT demo requires a schema-valid generated recording")
        cells = compare_com_oracle(native[-2:], response, "WinRT")
        generated = json.loads(response.read_text(encoding="utf-8").splitlines()[0])
        for index, field in ((0, "activation_hresult"), (2, "create_hresult")):
            actual = generated.get(field)
            if type(actual) is not int or native[index]["hresult"] != actual:
                raise ValueError(f"WinRT native parity mismatch: {field}")
            cells[field] = {"native": native[index]["hresult"], "generated": actual, "equal": True}
        result.update(native_oracle_compared=True, native_oracle_cells=cells,
                      native_oracle_stdout_sha256=oracle_sha256,
                      native_caller_windows_pid=native[0]["caller_pid"])
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
    demo.add_argument("--demo-winrt", action="store_true",
                      help="Run the owned WinRT facade once with native parity and official trace validation")
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
            or (not (args.demo_com or args.demo_winrt)
                and (args.oracle_stdout is not None or args.oracle_sha256 is not None))):
        parser.error("oracle stdout/hash are a paired option for --demo-com or --demo-winrt only")
    if ((args.whiny is None) != (args.whiny_sha256 is None)
            or (not (args.demo_com or args.demo_winrt)
                and (args.whiny is not None or args.whiny_sha256 is not None))):
        parser.error("whiny executable/hash are a paired option for --demo-com or --demo-winrt only")
    if args.demo_pid or args.demo_com or args.demo_winrt:
        if (not all((args.proxy_caller, args.wine, args.wine_sha256, args.wineserver_sha256,
                     args.proxy, args.builtin_root, args.runtime_root))
                or any((args.trace, args.response, args.request))
                or (args.demo_pid and args.expected_u32 is None)
                or ((args.demo_com or args.demo_winrt) and (
                    args.expected_u32 is not None or args.whiny is None))
                or (args.demo_winrt and args.oracle_stdout is None)):
            parser.error("demo requires proxy-caller/wine/runtime hashes/proxy/builtin-root/runtime-root; PID also requires expected-u32; object demos require whiny/whiny-sha256 and WinRT requires oracle stdout/hash; output paths are derived")
        arguments = (args.wine, args.wine_sha256, args.wineserver_sha256,
                     args.proxy_caller, args.proxy, args.builtin_root, args.config, args.runtime_root)
        if args.demo_pid:
            result = run_pid_demo(*arguments, args.expected_u32)
        else:
            invoke = run_winrt_demo if args.demo_winrt else run_com_demo
            result = invoke(*arguments, args.oracle_stdout, args.oracle_sha256, args.whiny, args.whiny_sha256)
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
