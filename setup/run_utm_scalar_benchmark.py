#!/usr/bin/env python3
"""Measure complete encrypted scalar calls across the Mac/UTM/Windows topology."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

try:
    from .run_topology_benchmark import percentile
except ImportError:
    from run_topology_benchmark import percentile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["native", "managed"], required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    arguments = parser.parse_args()
    if arguments.runs < 3:
        raise ValueError("at least three complete topology runs are required")

    samples = []
    with tempfile.TemporaryDirectory() as temporary:
        for index in range(arguments.runs):
            receipt = Path(temporary) / f"receipt-{index}.json"
            started = time.perf_counter_ns()
            completed = subprocess.run(
                [
                    "python3",
                    "setup/run_utm_scalar_e2e.py",
                    "--profile",
                    arguments.profile,
                    "--address",
                    arguments.address,
                    "--sudo-client",
                    "--manifest",
                    str(arguments.manifest),
                    "--client",
                    str(arguments.client),
                    "--receipt",
                    str(receipt),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            elapsed = time.perf_counter_ns() - started
            if completed.returncode != 0 or not receipt.is_file():
                raise RuntimeError(
                    f"topology run {index} failed exit={completed.returncode}: "
                    f"{completed.stdout}{completed.stderr}"
                )
            evidence = receipt.read_bytes()
            samples.append(
                {
                    "run": index + 1,
                    "elapsedNs": elapsed,
                    "receiptSha256": hashlib.sha256(evidence).hexdigest(),
                }
            )
    timings = [float(sample["elapsedNs"]) for sample in samples]
    document = {
        "schema": "wvb.windows-vm-scalar-benchmark.v1",
        "profile": arguments.profile,
        "address": arguments.address,
        "clock": "macos-process-perf-counter",
        "crossMachineSubtraction": False,
        "requestBytes": 8,
        "responseBytes": 4,
        "runs": samples,
        "p50Ns": percentile(timings, 0.50),
        "p95Ns": percentile(timings, 0.95),
        "p99Ns": percentile(timings, 0.99),
        "meanNs": statistics.fmean(timings),
        "minimumNs": min(timings),
        "maximumNs": max(timings),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"utm-scalar-benchmark=ok profile={arguments.profile} "
        f"runs={arguments.runs} output={arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
