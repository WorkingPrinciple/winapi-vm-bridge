#!/usr/bin/env python3
"""Run process-local topology timings without cross-machine clock subtraction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import time
from pathlib import Path


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        raise ValueError("at least one value is required")
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile_value)))
    return ordered[rank]


def measure(command: list[str], payload_bytes: int) -> dict[str, object]:
    environment = os.environ.copy()
    environment["WVB_BENCH_PAYLOAD_BYTES"] = str(payload_bytes)
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        env=environment,
    )
    elapsed = time.perf_counter_ns() - started
    if completed.returncode != 0:
        raise RuntimeError(
            f"benchmark command failed payload={payload_bytes} "
            f"exit={completed.returncode} stderr={completed.stderr.decode(errors='replace')}"
        )
    return {
        "elapsedNs": elapsed,
        "stdoutBytes": len(completed.stdout),
        "stdoutSha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderrBytes": len(completed.stderr),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command or arguments.runs < 3 or arguments.warmups < 0:
        raise ValueError("command and at least three runs are required")

    results = []
    for payload_bytes in [1, 4 * 1024, 64 * 1024, 1024 * 1024]:
        for _ in range(arguments.warmups):
            measure(command, payload_bytes)
        samples = [measure(command, payload_bytes) for _ in range(arguments.runs)]
        timings = [float(sample["elapsedNs"]) for sample in samples]
        results.append(
            {
                "payloadBytes": payload_bytes,
                "runs": arguments.runs,
                "p50Ns": percentile(timings, 0.50),
                "p95Ns": percentile(timings, 0.95),
                "p99Ns": percentile(timings, 0.99),
                "meanNs": statistics.fmean(timings),
                "minimumNs": min(timings),
                "maximumNs": max(timings),
                "stdoutBytes": samples[-1]["stdoutBytes"],
                "stdoutSha256": samples[-1]["stdoutSha256"],
                "stderrBytes": samples[-1]["stderrBytes"],
            }
        )
    document = {
        "schemaVersion": 1,
        "clock": "host-process-perf-counter",
        "crossMachineSubtraction": False,
        "command": command,
        "results": results,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"topology-benchmark=ok output={arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
