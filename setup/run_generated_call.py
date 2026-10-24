#!/usr/bin/env python3
"""Run one product call against an already-started, explicitly configured guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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


def run_proxy_call(wine: Path, caller: Path, proxy: Path, config: Path,
                   response: Path, trace: Path, expected_u32: int) -> dict:
    """Call a real generated PE export through an explicitly prepared Wine prefix."""
    prefix = os.environ.get("WINEPREFIX")
    if (not prefix or not (Path(prefix) / "system.reg").is_file()
            or not os.environ.get("WINEDLLPATH")
            or "WHINY_WINE_BOOTSTRAP" in os.environ):
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
                                       text=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("proxy call observation timed out; guest completion unknown; no retry") from error
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
            "route": "generated-proxy", "proxy_sha256": proxy_hash}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    executable = parser.add_mutually_exclusive_group(required=True)
    executable.add_argument("--wvb", type=Path)
    executable.add_argument("--proxy-caller", type=Path)
    parser.add_argument("--wine", type=Path)
    parser.add_argument("--proxy", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--expected-u32", type=int)
    args = parser.parse_args()
    if args.proxy_caller:
        if not all((args.wine, args.proxy, args.trace, args.expected_u32)):
            parser.error("proxy mode requires --wine, --proxy, --trace and --expected-u32")
        result = run_proxy_call(args.wine, args.proxy_caller, args.proxy, args.config,
                                args.response, args.trace, args.expected_u32)
    else:
        if args.request is None or any((args.wine, args.proxy, args.trace)):
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
