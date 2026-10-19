#!/usr/bin/env python3
"""Run one pre-authorized, correlated scalar call and emit its VM receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from .run_utm_deploy import push, require_target
    from .run_utm_scalar_e2e import pull_required
except ImportError:
    from run_utm_deploy import push, require_target
    from run_utm_scalar_e2e import pull_required


DEFAULT_UTMCTL = "/Applications/UTM.app/Contents/MacOS/utmctl"
DEFAULT_VM = "Whiny-Windows11-x64"
DEFAULT_UUID = "F659FCF2-AC83-4072-86A6-F7538781A1FC"
DEFAULT_DISK_UUID = "065112D9-3B2D-4E40-AF74-C6B29CA4D133"
DEFAULT_DISK_PATH = (
    "/Users/dragoshont/Library/Containers/com.utmapp.UTM/Data/Documents/"
    "Whiny-Windows11-x64.utm/Data/"
    "065112D9-3B2D-4E40-AF74-C6B29CA4D133.qcow2"
)
HOST_ID = "utm-WhinyWindows11x64-F659FCF2"
SOURCE_POLICY_SHA256 = (
    "0f0c3d4c6f45f1cb8ccdb095783c42f1aad116ea42a25d3e07e5c3d49a8b8876"
)


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_qemu_command(
    command: str, vm_uuid: str, disk_uuid: str, disk_path: str
) -> None:
    if (
        vm_uuid not in command
        or disk_uuid not in command
        or f"file.filename={disk_path}" not in command
        or " -snapshot " in f" {command} "
    ):
        raise RuntimeError("QEMU disk command identity mismatch")


def observe_disk(vm_uuid: str, disk_uuid: str, disk_path: str) -> dict[str, object]:
    processes = subprocess.run(
        ["ps", "ax", "-o", "pid=,command="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    matches = [line for line in processes if "qemu-x86_64-softmmu" in line and vm_uuid in line]
    if len(matches) != 1:
        raise RuntimeError(f"exact QEMU process mismatch: {matches}")
    pid_text, command = matches[0].strip().split(maxsplit=1)
    validate_qemu_command(command, vm_uuid, disk_uuid, disk_path)
    pid = int(pid_text)
    handles = subprocess.run(
        ["lsof", "-nP", "-a", "-p", str(pid)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    disk_handles = [line for line in handles if disk_path in line]
    if len(disk_handles) != 1 or "REG" not in disk_handles[0]:
        raise RuntimeError(f"QEMU disk handle mismatch: {disk_handles}")
    stat = Path(disk_path).stat()
    return {
        "vmUuid": vm_uuid,
        "diskUuid": disk_uuid,
        "diskPath": disk_path,
        "qemuPid": pid,
        "qemuStartedCommandSha256": hashlib.sha256(command.encode()).hexdigest(),
        "diskHandle": disk_handles[0],
        "diskInode": stat.st_ino,
        "diskBytes": stat.st_size,
        "snapshotFlag": False,
    }


def timestamp_ms(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() * 1000)


def canonical_timestamp(value: str) -> str:
    return datetime.fromisoformat(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def reserve_host_state(
    state: dict[str, object],
    *,
    sequence: int,
    challenge_sha256: str,
    attempt_id: str,
    authorization_sha256: str,
) -> dict[str, object]:
    if state.get("pending") is not None:
        raise RuntimeError("unreconciled pending runtime receipt attempt")
    if sequence != state["lastSequence"] + 1:
        raise RuntimeError("runtime receipt sequence is not monotonic")
    if challenge_sha256 in state["challenges"]:
        raise RuntimeError("runtime challenge was already used")
    output = dict(state)
    output["pending"] = {
        "sequence": sequence,
        "challengeSha256": challenge_sha256,
        "attemptId": attempt_id,
        "authorizationSha256": authorization_sha256,
    }
    return output


def complete_host_state(
    state: dict[str, object],
    *,
    sequence: int,
    challenge_sha256: str,
    attempt_id: str,
    receipt_sha256: str,
) -> dict[str, object]:
    pending = state.get("pending")
    if (
        not isinstance(pending, dict)
        or pending.get("sequence") != sequence
        or pending.get("attemptId") != attempt_id
        or pending.get("challengeSha256") != challenge_sha256
    ):
        raise RuntimeError("runtime receipt pending state changed unexpectedly")
    output = dict(state)
    output["lastSequence"] = sequence
    output["challenges"] = [*state["challenges"], challenge_sha256]
    output["pending"] = None
    output["completedAttempt"] = attempt_id
    output["receiptSha256"] = receipt_sha256
    return output


def run(command: list[str], *, input_bytes: bytes | None = None, check: bool = True):
    return subprocess.run(
        command, input=input_bytes, check=check, capture_output=True, text=False
    )


def cleanup_profile(
    *,
    utmctl: str,
    vm: str,
    profile: str,
    script: Path,
    evidence_dir: Path,
    root: str,
    retain_artifacts: bool,
) -> tuple[dict[str, object], Path]:
    guest_script = (
        r"C:\Users\Public\wvb-native-cleanup.ps1"
        if profile == "native"
        else r"C:\Users\Public\wvb-managed-cleanup.ps1"
    )
    guest_receipt = (
        r"C:\Users\Public\wvb-native-cleanup.json"
        if profile == "native"
        else r"C:\Users\Public\wvb-cleanup.json"
    )
    if retain_artifacts:
        rule = (
            "WvbAcceptance-native-scalar"
            if profile == "native"
            else "WvbAcceptance-canonical-runtime"
        )
        broker = (
            root + r"\payload\wvb-native-e2e.exe"
            if profile == "native"
            else root + r"\payload\wvb-managed-e2e.exe"
        )
        script_text = (
            "$ErrorActionPreference='Stop';"
            f"$broker='{broker}';"
            "$stopped=@();"
            "Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -eq $broker}|"
            "ForEach-Object {Stop-Process -Id $_.ProcessId -Force;$stopped += $_.ProcessId};"
            f"Remove-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue;"
            "$receipt=[ordered]@{RootRemoved=$false;ArtifactRootRetained=$true;"
            f"FirewallRuleRemoved=($null -eq (Get-NetFirewallRule -DisplayName '{rule}' "
            "-ErrorAction SilentlyContinue));StoppedPids=$stopped;"
            "Utc=(Get-Date).ToUniversalTime().ToString('o')};"
            f"[IO.File]::WriteAllBytes('{guest_receipt}',"
            "[Text.Encoding]::UTF8.GetBytes(($receipt|ConvertTo-Json -Compress)))"
        )
        command = [
            utmctl,
            "exec",
            vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script_text,
        ]
    else:
        push(utmctl, vm, script, guest_script)
        command = [
            utmctl,
            "exec",
            vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            guest_script,
            "-Root",
            root,
        ]
    completed = subprocess.run(command, check=False, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(f"{profile} cleanup command failed")
    receipt_bytes = pull_required(utmctl, vm, guest_receipt)
    receipt = json.loads(receipt_bytes.decode("utf-8-sig"))
    if not receipt["FirewallRuleRemoved"] or (
        not retain_artifacts and not receipt["RootRemoved"]
    ):
        raise RuntimeError(f"{profile} cleanup was incomplete")
    receipt_path = evidence_dir / f"{profile}-cleanup.json"
    receipt_path.write_bytes(receipt_bytes)
    return receipt, receipt_path


def observe_guest_identity(utmctl: str, vm: str, evidence_dir: Path) -> dict[str, object]:
    guest_path = r"C:\Users\Public\wvb-current-guest-identity.json"
    script = (
        "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
        "$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CurrentBuild=$cv.CurrentBuild;"
        "UBR=$cv.UBR;DisplayVersion=$cv.DisplayVersion;"
        "NowUtc=(Get-Date).ToUniversalTime().ToString('o')};"
        f"[IO.File]::WriteAllBytes('{guest_path}',"
        "[Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))"
    )
    completed = subprocess.run(
        [
            utmctl,
            "exec",
            vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("guest identity observation failed")
    evidence = pull_required(utmctl, vm, guest_path)
    value = json.loads(evidence.decode("utf-8-sig"))
    path = evidence_dir / "guest-identity.json"
    path.write_bytes(evidence)
    return value


def observe_guest_files(
    *,
    utmctl: str,
    vm: str,
    profile: str,
    deployment: dict[str, object],
    evidence_dir: Path,
) -> tuple[dict[str, dict[str, object]], Path]:
    files = deployment["Files"]
    items = [
        {
            "Key": key,
            "Path": value["Path"],
            "Expected": value["Hash"],
        }
        for key, value in files.items()
    ]
    guest_evidence = rf"C:\Users\Public\wvb-{profile}-loaded-files.json"
    script = (
        "$ErrorActionPreference='Stop';"
        f"$items=ConvertFrom-Json '{json.dumps(items, separators=(',', ':'))}';"
        "$rows=@($items|ForEach-Object {"
        "$actual=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.Path).Hash.ToLowerInvariant();"
        "[pscustomobject]@{Key=$_.Key;Path=$_.Path;Expected=$_.Expected;Actual=$actual;"
        "Matches=($actual -eq $_.Expected);Length=(Get-Item -LiteralPath $_.Path).Length}});"
        f"[IO.File]::WriteAllBytes('{guest_evidence}',"
        "[Text.Encoding]::UTF8.GetBytes(($rows|ConvertTo-Json -Compress)))"
    )
    completed = subprocess.run(
        [
            utmctl,
            "exec",
            vm,
            "--cmd",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("guest loaded-file observation failed")
    evidence = pull_required(utmctl, vm, guest_evidence)
    rows = json.loads(evidence.decode("utf-8-sig"))
    if isinstance(rows, dict):
        rows = [rows]
    if not rows or any(not row["Matches"] for row in rows):
        raise RuntimeError(f"guest loaded-file hash mismatch: {rows}")
    observed = {row["Key"]: row for row in rows}
    if set(observed) != set(files):
        raise RuntimeError("guest loaded-file identity set mismatch")
    evidence_path = evidence_dir / f"{profile}-loaded-files.json"
    evidence_path.write_bytes(evidence)
    return observed, evidence_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["native", "managed"], required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--cleanup-script", type=Path, required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--retain-artifacts", action="store_true")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--host-state", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, default=Path("target/release/wvb-runtime"))
    parser.add_argument("--receipt-cli", type=Path, default=Path("target/release/wvb-receipt"))
    parser.add_argument("--utmctl", default=DEFAULT_UTMCTL)
    parser.add_argument("--vm", default=DEFAULT_VM)
    parser.add_argument("--expected-uuid", default=DEFAULT_UUID)
    parser.add_argument("--expected-disk-uuid", default=DEFAULT_DISK_UUID)
    parser.add_argument("--expected-disk-path", default=DEFAULT_DISK_PATH)
    arguments = parser.parse_args()

    require_target(arguments.utmctl, arguments.vm, arguments.expected_uuid)
    disk = observe_disk(
        arguments.expected_uuid,
        arguments.expected_disk_uuid,
        arguments.expected_disk_path,
    )
    package = json.loads(arguments.manifest.read_text())
    profile = package[arguments.profile]
    arguments.evidence_dir.mkdir(parents=True, exist_ok=True)
    arguments.state.parent.mkdir(parents=True, exist_ok=True)
    if not arguments.state.exists():
        run([str(arguments.runtime), "init-state", "--state", str(arguments.state)])
    guest_identity = observe_guest_identity(
        arguments.utmctl, arguments.vm, arguments.evidence_dir
    )

    host_state = (
        json.loads(arguments.host_state.read_text())
        if arguments.host_state.exists()
        else {"lastSequence": 0, "challenges": [], "pending": None}
    )
    workload_id = os.urandom(16)
    attempt_id = os.urandom(16)
    receipt_id = os.urandom(16)
    actor_id = os.urandom(16)
    actor_public_key = os.urandom(32)
    trace_id = os.urandom(16)
    challenge = bytearray(os.urandom(32))
    seed = bytearray(os.urandom(32))
    challenge_hash = sha256_bytes(challenge).hex()
    issued_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    authorization = {
        "schema": "winapi-vm-bridge.authorization-evidence.v2",
        "issuedAt": issued_at,
        "hostId": HOST_ID,
        "workloadId": workload_id.hex(),
        "attemptId": attempt_id.hex(),
        "receiptId": receipt_id.hex(),
        "challengeSha256": challenge_hash,
        "sequence": arguments.sequence,
        "profile": arguments.profile,
        "bundleSha256": profile["bundleSha256"],
        "contractSha256": profile["contractSha256"],
        "operationId": profile["operationId"],
        "requestSchemaId": profile["requestSchemaId"],
        "responseSchemaId": profile["responseSchemaId"],
        "address": arguments.address,
        "clientSha256": sha256(arguments.client),
        "files": profile["files"],
        "target": disk,
        "guestIdentity": guest_identity,
    }
    authorization_path = arguments.evidence_dir / f"{arguments.profile}-authorization.json"
    authorization_path.write_bytes(canonical(authorization) + b"\n")
    authorization_sha256 = sha256(authorization_path)
    challenge_path = arguments.evidence_dir / f"{arguments.profile}-challenge.bin"
    challenge_path.write_bytes(challenge)
    host_state = reserve_host_state(
        host_state,
        sequence=arguments.sequence,
        challenge_sha256=challenge_hash,
        attempt_id=attempt_id.hex(),
        authorization_sha256=authorization_sha256,
    )
    arguments.host_state.parent.mkdir(parents=True, exist_ok=True)
    arguments.host_state.write_bytes(canonical(host_state) + b"\n")

    request_hash = sha256_bytes(
        (20).to_bytes(4, "little", signed=True)
        + (22).to_bytes(4, "little", signed=True)
    )
    response_hash = sha256_bytes((42).to_bytes(4, "little", signed=True))
    correlation = {
        "workload_id": list(workload_id),
        "attempt_id": list(attempt_id),
        "host_id": HOST_ID,
        "bundle_sha256": list(bytes.fromhex(profile["bundleSha256"])),
        "operation_id": profile["operationId"],
        "request_sha256": list(request_hash),
        "receipt_id": None,
    }
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        correlation_path = temp / "correlation.json"
        correlation_path.write_text(json.dumps(correlation), encoding="utf-8")
        run(
            [
                str(arguments.runtime),
                "begin-attempt",
                "--state",
                str(arguments.state),
                "--correlation",
                str(correlation_path),
                "--actor-id",
                actor_id.hex(),
                "--actor-public-key",
                actor_public_key.hex(),
                "--trace-id",
                trace_id.hex(),
                "--now-unix-ms",
                str(timestamp_ms(issued_at)),
            ]
        )
        raw_receipt = arguments.evidence_dir / f"{arguments.profile}-call.json"
        call = subprocess.run(
            [
                "python3",
                "setup/run_utm_scalar_e2e.py",
                "--profile",
                arguments.profile,
                "--address",
                arguments.address,
                "--sudo-client",
                "--attempt-id",
                attempt_id.hex(),
                "--authorization-sha256",
                authorization_sha256,
                "--manifest",
                str(arguments.manifest),
                "--client",
                str(arguments.client),
                "--root",
                arguments.root,
                "--receipt",
                str(raw_receipt),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if call.returncode != 0:
            raise RuntimeError(f"correlated call failed: {call.stdout}{call.stderr}")
        observed = json.loads(raw_receipt.read_text())
        if (
            observed["attemptId"] != attempt_id.hex()
            or observed["authorizationSha256"] != authorization_sha256
            or attempt_id.hex() not in observed["serverLog"]
            or authorization_sha256 not in observed["serverLog"]
        ):
            raise RuntimeError("executed call did not consume pre-authorization identity")

        loaded_files, loaded_files_path = observe_guest_files(
            utmctl=arguments.utmctl,
            vm=arguments.vm,
            profile=arguments.profile,
            deployment=observed["deployment"],
            evidence_dir=arguments.evidence_dir,
        )
        cleanup, cleanup_path = cleanup_profile(
            utmctl=arguments.utmctl,
            vm=arguments.vm,
            profile=arguments.profile,
            script=arguments.cleanup_script,
            evidence_dir=arguments.evidence_dir,
            root=arguments.root,
            retain_artifacts=arguments.retain_artifacts,
        )
        terminal = {
            "receipt_id": list(receipt_id),
            "bundle_sha256": list(bytes.fromhex(profile["bundleSha256"])),
            "contract_sha256": list(bytes.fromhex(profile["contractSha256"])),
            "operation_id": profile["operationId"],
            "request_sha256": list(request_hash),
            "response_sha256": list(response_hash),
            "status": "ok",
            "runtime_identity": {
                "host_id": HOST_ID,
                "os_build": (
                    f"Windows 11 10.0.{guest_identity['CurrentBuild']}."
                    f"{guest_identity['UBR']}"
                ),
                "architecture": "x86-64",
                "bridge_version": "0.2.0",
            },
            "loaded_files": [
                {
                    "path": entry["relativePath"],
                    "sha256": list(bytes.fromhex(loaded_files[entry["key"]]["Actual"])),
                }
                for entry in profile["files"]
                if entry["key"] not in {"Contract"}
            ],
            "authorization_receipt_sha256": list(
                bytes.fromhex(authorization_sha256)
            ),
            "challenge_sha256": list(bytes.fromhex(challenge_hash)),
            "sequence": arguments.sequence,
            "started_at": canonical_timestamp(observed["startedAt"]),
            "completed_at": canonical_timestamp(observed["completedAt"]),
            "completed_unix_ms": timestamp_ms(observed["completedAt"]),
            "cleanup": {
                "status": "verified",
                "diagnostics": [
                    f"cleanup-receipt-sha256={sha256(cleanup_path)}",
                    f"root-removed={str(cleanup.get('RootRemoved', False)).lower()}",
                    f"artifact-root-retained={str(cleanup.get('ArtifactRootRetained', False)).lower()}",
                    "firewall-rule-removed=true",
                ],
            },
        }
        terminal_path = temp / "terminal.json"
        terminal_path.write_text(json.dumps(terminal), encoding="utf-8")
        runtime_receipt = (
            arguments.evidence_dir / f"{arguments.profile}-runtime-receipt.json"
        )
        public_key = arguments.evidence_dir / f"{arguments.profile}-public-key.bin"
        try:
            run(
                [
                    str(arguments.runtime),
                    "complete-receipt",
                    "--state",
                    str(arguments.state),
                    "--correlation",
                    str(correlation_path),
                    "--input",
                    str(terminal_path),
                    "--output",
                    str(runtime_receipt),
                    "--public-key",
                    str(public_key),
                ],
                input_bytes=bytes(seed),
            )
            replay = run(
                [
                    str(arguments.runtime),
                    "complete-receipt",
                    "--state",
                    str(arguments.state),
                    "--correlation",
                    str(correlation_path),
                    "--input",
                    str(terminal_path),
                    "--output",
                    str(temp / "replayed.json"),
                    "--public-key",
                    str(temp / "replayed-key.bin"),
                ],
                input_bytes=os.urandom(32),
                check=False,
            )
            if replay.returncode == 0:
                raise RuntimeError("terminal receipt replay unexpectedly succeeded")
            run(
                [
                    str(arguments.receipt_cli),
                    "verify",
                    "--input",
                    str(runtime_receipt),
                    "--public-key",
                    str(public_key),
                ]
            )
        finally:
            seed[:] = b"\0" * len(seed)

    receipt = json.loads(runtime_receipt.read_text())
    signer = {
        "name": f"{arguments.profile}-windows-vm",
        "bundle_sha256": profile["bundleSha256"],
        "host_ids": [HOST_ID],
        "key_id": receipt["authentication"]["key_id"],
        "public_key_file": public_key.name,
        "public_key_hex": public_key.read_bytes().hex(),
        "scope": "acceptance-only",
        "production_runtime_identity": False,
    }
    signer_path = arguments.evidence_dir / f"{arguments.profile}-signer.json"
    signer_path.write_bytes(canonical(signer) + b"\n")
    host_state = complete_host_state(
        host_state,
        sequence=arguments.sequence,
        challenge_sha256=challenge_hash,
        attempt_id=attempt_id.hex(),
        receipt_sha256=sha256(runtime_receipt),
    )
    arguments.host_state.write_bytes(canonical(host_state) + b"\n")
    summary = {
        "schema": "wvb.correlated-vm-acceptance.v1",
        "profile": arguments.profile,
        "authorizationSha256": authorization_sha256,
        "challengeSha256": challenge_hash,
        "attemptId": attempt_id.hex(),
        "runtimeReceiptSha256": sha256(runtime_receipt),
        "cleanupSha256": sha256(cleanup_path),
        "loadedFilesSha256": sha256(loaded_files_path),
        "replayRejected": True,
        "disk": disk,
    }
    summary_path = arguments.evidence_dir / f"{arguments.profile}-summary.json"
    summary_path.write_bytes(canonical(summary) + b"\n")
    print(
        f"utm-correlated-acceptance=ok profile={arguments.profile} "
        f"receiptSha256={summary['runtimeReceiptSha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
