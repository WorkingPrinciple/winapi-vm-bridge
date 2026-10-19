#!/usr/bin/env python3
"""Upload and wait for one isolated Windows-RPC acceptance deployment."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VmEntry:
    uuid: str
    status: str
    name: str


def parse_vm_list(output: str) -> list[VmEntry]:
    entries = []
    for line in output.splitlines()[1:]:
        columns = line.split(maxsplit=2)
        if len(columns) == 3:
            entries.append(VmEntry(columns[0].upper(), columns[1], columns[2]))
    return entries


def require_target(utmctl: str, vm: str, expected_uuid: str) -> None:
    completed = subprocess.run(
        [utmctl, "list"], check=True, capture_output=True, text=True
    )
    matches = [entry for entry in parse_vm_list(completed.stdout) if entry.name == vm]
    if (
        len(matches) != 1
        or matches[0].uuid != expected_uuid.upper()
        or matches[0].status != "started"
    ):
        raise RuntimeError(
            f"target identity/readiness mismatch: expected={vm}/{expected_uuid} "
            f"observed={matches}"
        )


def push(utmctl: str, vm: str, source: Path, destination: str) -> None:
    completed = subprocess.run(
        [utmctl, "file", "push", vm, destination],
        input=source.read_bytes(),
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"failed to upload {source} to {destination}")


def pull(utmctl: str, vm: str, path: str) -> bytes | None:
    completed = subprocess.run(
        [utmctl, "file", "pull", vm, path],
        capture_output=True,
        check=False,
    )
    diagnostic = completed.stdout + completed.stderr
    if completed.returncode != 0 or b"failed to open file" in diagnostic:
        return None
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--utmctl", default="/Applications/UTM.app/Contents/MacOS/utmctl")
    parser.add_argument("--vm", required=True)
    parser.add_argument("--expected-uuid", required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--guest-script", default=r"C:\Users\Public\wvb-deploy.ps1")
    parser.add_argument(
        "--error-path", default=r"C:\Users\Public\wvb-deploy-error.txt"
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument(
        "--upload",
        action="append",
        default=[],
        help="LOCAL::WINDOWS_PATH",
    )
    arguments = parser.parse_args()

    require_target(arguments.utmctl, arguments.vm, arguments.expected_uuid)
    for mapping in arguments.upload:
        source, separator, destination = mapping.partition("::")
        if not separator:
            raise RuntimeError(f"invalid upload mapping {mapping}")
        push(arguments.utmctl, arguments.vm, Path(source), destination)
    push(arguments.utmctl, arguments.vm, arguments.script, arguments.guest_script)

    deployment_id = uuid.uuid4().hex
    subprocess.run(
        [
            arguments.utmctl,
            "exec",
            arguments.vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            arguments.guest_script,
            "-Root",
            arguments.root,
            "-ListenAddress",
            arguments.listen_address,
            "-DeploymentId",
            deployment_id,
        ],
        check=False,
    )
    done_path = arguments.root + rf"\deploy-{deployment_id}.done"
    for _ in range(max(1, arguments.timeout_seconds // 2)):
        done = pull(arguments.utmctl, arguments.vm, done_path)
        if done is not None and done.decode("ascii", errors="ignore").strip() == "PASS":
            print(f"utm-deploy=ok vm={arguments.vm} root={arguments.root}")
            return 0
        error = pull(
            arguments.utmctl,
            arguments.vm,
            arguments.error_path,
        )
        if error:
            raise RuntimeError(error.decode("utf-8-sig", errors="replace"))
        time.sleep(2)
    raise RuntimeError("UTM deployment timed out")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_utm_deploy: {error}", file=sys.stderr)
        raise SystemExit(2)
