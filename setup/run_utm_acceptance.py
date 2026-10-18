#!/usr/bin/env python3
"""Identity-bound, reversible preflight for the isolated Windows acceptance VM."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_UTMCTL = "/Applications/UTM.app/Contents/MacOS/utmctl"
DEFAULT_VM = "Whiny-Windows11-x64"
DEFAULT_UUID = "F659FCF2-AC83-4072-86A6-F7538781A1FC"


@dataclass(frozen=True)
class VmEntry:
    uuid: str
    status: str
    name: str


def parse_vm_list(output: str) -> list[VmEntry]:
    entries: list[VmEntry] = []
    for line in output.splitlines()[1:]:
        columns = line.split(maxsplit=2)
        if len(columns) != 3:
            continue
        entries.append(VmEntry(columns[0].upper(), columns[1], columns[2]))
    return entries


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def exact_target(entries: list[VmEntry], vm: str, expected_uuid: str) -> VmEntry:
    matches = [entry for entry in entries if entry.name == vm]
    if len(matches) != 1 or matches[0].uuid != expected_uuid.upper():
        raise RuntimeError(
            f"target identity mismatch: expected {vm} {expected_uuid}, observed={matches}"
        )
    return matches[0]


def ensure_snapshot(utmctl: str, vm: str, name: str) -> None:
    snapshots = run([utmctl, "snapshot", "list", vm]).stdout
    if any(line.split("\t", 1)[0] == name for line in snapshots.splitlines()):
        return
    run([utmctl, "snapshot", "create", vm, "--name", name])


def guest_identity(utmctl: str, vm: str) -> dict[str, object]:
    script = (
        "$o=[ordered]@{"
        "ComputerName=$env:COMPUTERNAME;"
        "User=$env:USERNAME;"
        "Os=(Get-CimInstance Win32_OperatingSystem).Caption;"
        "Version=(Get-CimInstance Win32_OperatingSystem).Version;"
        "Arch=$env:PROCESSOR_ARCHITECTURE;"
        "Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"
        ".ToUniversalTime().ToString('o');"
        "Ips=@(Get-NetIPAddress -AddressFamily IPv4|"
        "Where-Object {$_.IPAddress -ne '127.0.0.1'}|"
        "Select-Object -ExpandProperty IPAddress)"
        "};$o|ConvertTo-Json -Compress"
    )
    completed = run(
        [
            utmctl,
            "exec",
            vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-Command",
            script,
        ],
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.lstrip().startswith("{"):
        diagnostic = (completed.stdout + completed.stderr).strip()
        raise RuntimeError(
            "guest readiness unavailable; no guest mutation performed: "
            + diagnostic
        )
    value = json.loads(completed.stdout)
    if not value.get("ComputerName") or not value.get("Version"):
        raise RuntimeError("guest identity response is incomplete")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--utmctl", default=DEFAULT_UTMCTL)
    parser.add_argument("--vm", default=DEFAULT_VM)
    parser.add_argument("--expected-uuid", default=DEFAULT_UUID)
    parser.add_argument(
        "--snapshot-name",
        default="wvb-pre-acceptance-20261018",
    )
    parser.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()

    entries = parse_vm_list(run([arguments.utmctl, "list"]).stdout)
    target = exact_target(entries, arguments.vm, arguments.expected_uuid)
    if target.status != "started":
        raise RuntimeError(f"target is not started: {target.status}")
    ensure_snapshot(arguments.utmctl, arguments.vm, arguments.snapshot_name)
    identity = guest_identity(arguments.utmctl, arguments.vm)
    receipt = {
        "schemaVersion": 1,
        "vm": asdict(target),
        "snapshot": arguments.snapshot_name,
        "guest": identity,
        "checkedAt": datetime.now(UTC).isoformat(),
        "mutationAuthorized": False,
        "next": "deploy only to a dedicated root with scoped rules and cleanup",
    }
    arguments.receipt.parent.mkdir(parents=True, exist_ok=True)
    arguments.receipt.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"utm-acceptance-preflight=ok vm={target.name} uuid={target.uuid} "
        f"receipt={arguments.receipt}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_utm_acceptance: {error}", file=sys.stderr)
        raise SystemExit(2)
