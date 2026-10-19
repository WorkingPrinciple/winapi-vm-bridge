#!/usr/bin/env python3
"""Finalize the strict trust policy and evidence manifest for correlated VM receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_POLICY_SHA256 = (
    "0f0c3d4c6f45f1cb8ccdb095783c42f1aad116ea42a25d3e07e5c3d49a8b8876"
)
HOST_ID = "utm-WhinyWindows11x64-F659FCF2"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    arguments = parser.parse_args()
    signers = [
        json.loads((arguments.evidence / f"{profile}-signer.json").read_text())
        for profile in ("native", "managed")
    ]
    policy = {
        "schema": "whiny.runtime-receipt.trust-policy.v1",
        "scheme": "ed25519",
        "signing_domain": "whiny.runtime-receipt.v1\\u0000",
        "source_policy_sha256": SOURCE_POLICY_SHA256,
        "host_ids": [HOST_ID],
        "historical_invalid_receipts": [
            "../windows-vm-runtime-receipts-v1-posthoc-invalid/"
            "native-runtime-receipt.json",
            "../windows-vm-runtime-receipts-v1-posthoc-invalid/"
            "managed-runtime-receipt.json",
        ],
        "signers": signers,
    }
    policy_path = arguments.evidence / "whiny-trust-policy.json"
    policy_path.write_bytes(canonical(policy) + b"\n")
    files = [
        path
        for path in sorted(arguments.evidence.iterdir())
        if path.is_file() and path.name != "evidence-manifest.json"
    ]
    manifest = {
        "schema": "wvb.correlated-windows-vm-runtime-evidence.v1",
        "vm_uuid": "F659FCF2-AC83-4072-86A6-F7538781A1FC",
        "disk_uuid": "065112D9-3B2D-4E40-AF74-C6B29CA4D133",
        "host_id": HOST_ID,
        "runtime_state_sha256": sha256(arguments.state),
        "files": [
            {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
            for path in files
        ],
    }
    manifest_path = arguments.evidence / "evidence-manifest.json"
    manifest_path.write_bytes(canonical(manifest) + b"\n")
    print(
        f"vm-runtime-evidence=ok manifestSha256={sha256(manifest_path)} "
        f"policySha256={sha256(policy_path)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
