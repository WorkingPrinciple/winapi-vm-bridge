#!/usr/bin/env python3
"""Create the canonical manifest for committed Windows VM acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    files = [
        path
        for path in sorted(arguments.evidence.iterdir())
        if path.is_file() and path.resolve() != arguments.output.resolve()
    ]
    document = {
        "schema": "wvb.windows-vm-acceptance-evidence.v1",
        "repository": "dragoshont/winapi-vm-bridge",
        "whinySourceCommit": "97fe515268a83522b31fcf11f1c82bb329c9d702",
        "vmUuid": "F659FCF2-AC83-4072-86A6-F7538781A1FC",
        "diskUuid": "065112D9-3B2D-4E40-AF74-C6B29CA4D133",
        "profiles": ["native-scalar", "managed-scalar"],
        "excludedProfiles": ["shell_hook", "nt_wait_completion", "alpc"],
        "externalHolds": ["signing", "notarization", "publication", "hosted-ci"],
        "files": [
            {
                "path": path.name,
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in files
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"windows-vm-evidence=ok output={arguments.output} "
        f"sha256={sha256(arguments.output)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
