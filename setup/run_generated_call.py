#!/usr/bin/env python3
"""Run one product call against an already-started, explicitly configured guest."""

import argparse
import json
from pathlib import Path
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wvb", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--expected-u32", type=int)
    args = parser.parse_args()
    print(json.dumps(run_call(args.wvb, args.config, args.request, args.response,
                              args.expected_u32), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"run_generated_call: {error}", file=sys.stderr)
        raise SystemExit(2)
