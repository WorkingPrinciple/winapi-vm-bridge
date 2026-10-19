#!/usr/bin/env python3
"""Emit correlated acceptance-only VM runtime receipts with ephemeral Ed25519 keys."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path


SOURCE_POLICY_SHA256 = (
    "0f0c3d4c6f45f1cb8ccdb095783c42f1aad116ea42a25d3e07e5c3d49a8b8876"
)
HOST_ID = "utm-WhinyWindows11x64-F659FCF2"


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identifier(label: str, evidence: bytes) -> bytes:
    return sha256_bytes(label.encode("ascii") + b"\0" + evidence)[:16]


def timestamp_ms(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() * 1000)


def canonical_timestamp(value: str) -> str:
    return datetime.fromisoformat(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(command: list[str], *, input_bytes: bytes | None = None) -> None:
    subprocess.run(command, input=input_bytes, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, default=Path("target/release/wvb-runtime"))
    parser.add_argument("--receipt", type=Path, default=Path("target/release/wvb-receipt"))
    arguments = parser.parse_args()
    if arguments.output.exists():
        raise RuntimeError(f"immutable output already exists: {arguments.output}")
    arguments.output.mkdir(parents=True)
    arguments.state.parent.mkdir(parents=True, exist_ok=True)
    arguments.state.unlink(missing_ok=True)
    run([str(arguments.runtime), "init-state", "--state", str(arguments.state)])

    profiles = {
        "native": {
            "bundle": "67330e6444fdb8876d8c162692b544a891cc47d15d8140c3bd92f0ab6e51d828",
            "contract": "b40ca13272e1b0ce29a8dd489a22e727db287981a7d2d2d2e48301e5d6e96c47",
            "operation": 1,
            "files": [
                ("payload/dispatcher.dll", "af0df10d005a149c10dc3134e22e63a2e2962990d0aa5c164a5742dd57e10cdf"),
                ("payload/target/native_math.dll", "f1c49f073076e540e43592f7d12ecc27d8cb5a8c5983c6b6fd81f2924d4f60ee"),
            ],
        },
        "managed": {
            "bundle": "0086d567312afc118e0e4b31dad37ac108af7428c0b718bf329b6115ed773678",
            "contract": "490ad75fcf53f28215e8464740ff7e5995b38a8cbef2f8f0626ef5a7ec2c5414",
            "operation": 1,
            "files": [
                ("runtime/host/nethost.dll", "b7ebee5df9d8e27aca714db5be487aba5f00a24687e2e920b385444ae4f085d0"),
                ("runtime/dotnet/host/fxr/8.0.32/hostfxr.dll", "d579c8d05dd7456be1551ab0cc3a86bd298b5cd5675936332cc4c8e56e59984d"),
                ("payload/wvb_managed_host.dll", "2f8b176b05dad63c5a7488a3f6a4c17ce81eedab9d449c1a3734bcf8bcc7aa60"),
                ("payload/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json", "ca8666237d92cc378ef2cf0e34c09ec9f64ce3ed0b0e82d3333b83594da4cab0"),
                ("payload/ExampleManagedMath.WhinyDispatcher.dll", "8f4c98ecc0e5ba10c6f409214d3c37cd51d42229a4aab4c787c2b37f519e97fa"),
                ("payload/Example.ManagedMath.dll", "23cacc61dcebbab73d78aa8e4c97b08f8f664bae4c7af0603b2a1c4beea2a0f5"),
            ],
        },
    }
    request_hash = sha256_bytes((20).to_bytes(4, "little", signed=True) + (22).to_bytes(4, "little", signed=True))
    response_hash = sha256_bytes((42).to_bytes(4, "little", signed=True))
    signers = []
    evidence_files = []

    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        for sequence, (name, profile) in enumerate(profiles.items(), start=1):
            evidence_path = arguments.evidence_dir / f"{name}-vm-receipt.json"
            cleanup_path = arguments.evidence_dir / f"{name}-cleanup.json"
            evidence = evidence_path.read_bytes()
            cleanup = json.loads(cleanup_path.read_text(encoding="utf-8-sig"))
            observed = json.loads(evidence)
            if observed["status"] != "PASS" or observed["assertion"] != "result=42":
                raise RuntimeError(f"{name} positive VM evidence is not PASS")
            if not cleanup["RootRemoved"] or not cleanup["FirewallRuleRemoved"]:
                raise RuntimeError(f"{name} cleanup evidence is incomplete")

            workload_id = identifier(f"{name}-workload", evidence)
            attempt_id = identifier(f"{name}-attempt", evidence)
            receipt_id = identifier(f"{name}-receipt", evidence)
            actor_id = identifier(f"{name}-actor", evidence)
            actor_public_key = sha256_bytes(
                b"runtime-owner-acceptance-actor\0" + evidence
            )
            trace_id = identifier(f"{name}-trace", evidence)
            challenge = bytearray(os.urandom(32))
            seed = bytearray(os.urandom(32))
            challenge_hash = sha256_bytes(challenge)
            correlation = {
                "workload_id": list(workload_id),
                "attempt_id": list(attempt_id),
                "host_id": HOST_ID,
                "bundle_sha256": list(bytes.fromhex(profile["bundle"])),
                "operation_id": profile["operation"],
                "request_sha256": list(request_hash),
                "receipt_id": None,
            }
            terminal = {
                "receipt_id": list(receipt_id),
                "bundle_sha256": list(bytes.fromhex(profile["bundle"])),
                "contract_sha256": list(bytes.fromhex(profile["contract"])),
                "operation_id": profile["operation"],
                "request_sha256": list(request_hash),
                "response_sha256": list(response_hash),
                "status": "ok",
                "runtime_identity": {
                    "host_id": HOST_ID,
                    "os_build": "Windows 11 10.0.26300.9457",
                    "architecture": "x86-64",
                    "bridge_version": "0.2.0",
                },
                "loaded_files": [
                    {"path": path, "sha256": list(bytes.fromhex(digest))}
                    for path, digest in profile["files"]
                ],
                "authorization_receipt_sha256": list(
                    bytes.fromhex(observed["deploymentSha256"])
                ),
                "challenge_sha256": list(challenge_hash),
                "sequence": sequence,
                "started_at": canonical_timestamp(observed["startedAt"]),
                "completed_at": canonical_timestamp(observed["completedAt"]),
                "completed_unix_ms": timestamp_ms(observed["completedAt"]),
                "cleanup": {
                    "status": "verified",
                    "diagnostics": [],
                },
            }
            correlation_path = temporary_root / f"{name}-correlation.json"
            terminal_path = temporary_root / f"{name}-input.json"
            correlation_path.write_text(json.dumps(correlation), encoding="utf-8")
            terminal_path.write_text(json.dumps(terminal), encoding="utf-8")
            receipt_path = arguments.output / f"{name}-runtime-receipt.json"
            public_key_path = arguments.output / f"{name}-public-key.bin"
            challenge_path = arguments.output / f"{name}-challenge.bin"
            challenge_path.write_bytes(challenge)
            try:
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
                        str(timestamp_ms(observed["startedAt"])),
                    ]
                )
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
                        str(receipt_path),
                        "--public-key",
                        str(public_key_path),
                    ],
                    input_bytes=bytes(seed),
                )
                run(
                    [
                        str(arguments.receipt),
                        "verify",
                        "--input",
                        str(receipt_path),
                        "--public-key",
                        str(public_key_path),
                    ]
                )
            finally:
                seed[:] = b"\0" * len(seed)
            receipt = json.loads(receipt_path.read_text())
            public_key = public_key_path.read_bytes()
            signers.append(
                {
                    "name": f"{name}-windows-vm",
                    "bundle_sha256": profile["bundle"],
                    "host_ids": [HOST_ID],
                    "key_id": receipt["authentication"]["key_id"],
                    "public_key_file": public_key_path.name,
                    "public_key_hex": public_key.hex(),
                    "scope": "acceptance-only",
                    "production_runtime_identity": False,
                }
            )
            evidence_files.extend([receipt_path, public_key_path, challenge_path])

    policy_path = arguments.output / "whiny-trust-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema": "whiny.runtime-receipt.trust-policy.v1",
                "scheme": "ed25519",
                "signing_domain": "whiny.runtime-receipt.v1\\u0000",
                "source_policy_sha256": SOURCE_POLICY_SHA256,
                "host_ids": [HOST_ID],
                "historical_invalid_receipts": [],
                "signers": signers,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    evidence_files.append(policy_path)
    manifest = {
        "schema": "wvb.windows-vm-runtime-evidence.v1",
        "vm_uuid": "F659FCF2-AC83-4072-86A6-F7538781A1FC",
        "disk_uuid": "065112D9-3B2D-4E40-AF74-C6B29CA4D133",
        "host_id": HOST_ID,
        "runtime_state_sha256": sha256(arguments.state),
        "files": [
            {"path": path.name, "sha256": sha256(path)}
            for path in sorted(evidence_files)
        ],
    }
    manifest_path = arguments.output / "evidence-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"vm-runtime-receipts=ok output={arguments.output} "
        f"manifestSha256={sha256(manifest_path)} stateSha256={sha256(arguments.state)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
