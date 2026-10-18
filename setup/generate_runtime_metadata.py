#!/usr/bin/env python3
"""Generate deterministic unsigned SPDX and provenance metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def spdx_document(metadata: dict[str, Any], source_sha: str) -> dict[str, Any]:
    packages = sorted(
        metadata["packages"],
        key=lambda package: (package["name"], package["version"], package["id"]),
    )
    spdx_packages = []
    relationships = []
    for package in packages:
        spdx_id = "SPDXRef-Package-" + hashlib.sha256(
            f"{package['name']}@{package['version']}:{package['id']}".encode()
        ).hexdigest()[:24]
        license_value = package.get("license") or "NOASSERTION"
        spdx_packages.append(
            {
                "SPDXID": spdx_id,
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": license_value,
                "licenseDeclared": license_value,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:cargo/{package['name']}@{package['version']}"
                        ),
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            }
        )
    namespace = (
        "https://github.com/dragoshont/winapi-vm-bridge/spdx/"
        + hashlib.sha256(source_sha.encode()).hexdigest()
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "winapi-vm-bridge-runtime",
        "documentNamespace": namespace,
        "creationInfo": {
            "creators": ["Tool: setup/generate_runtime_metadata.py"],
            "created": "1970-01-01T00:00:00Z",
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def provenance_document(
    metadata: dict[str, Any],
    source_sha: str,
    sbom_sha256: str,
    subjects: list[dict[str, object]],
    commands: list[str],
) -> dict[str, Any]:
    rust_version = metadata.get("version", 1)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": sorted(subjects, key=lambda subject: str(subject["name"])),
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/dragoshont/winapi-vm-bridge/runtime-build/v1",
                "externalParameters": {
                    "sourceSha256": source_sha,
                    "cargoMetadataFormatVersion": rust_version,
                },
                "internalParameters": {
                    "commands": commands
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/dragoshont/winapi-vm-bridge",
                        "digest": {"sha256": source_sha},
                    },
                    {
                        "uri": "spdx:runtime-sbom",
                        "digest": {"sha256": sbom_sha256},
                    },
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/dragoshont/winapi-vm-bridge/local-unsigned"
                },
                "metadata": {"invocationId": None},
                "byproducts": [],
            },
        },
        "signatures": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="final unsigned artifact to bind into provenance",
    )
    arguments = parser.parse_args()
    if len(arguments.source_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in arguments.source_sha256
    ):
        raise ValueError("source SHA-256 must be 64 lowercase hexadecimal characters")
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    arguments.output.mkdir(parents=True, exist_ok=True)
    subjects = []
    for mapping in arguments.artifact:
        name, separator, path = mapping.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"invalid artifact mapping: {mapping}")
        artifact = Path(path)
        if not artifact.is_file():
            raise ValueError(f"artifact is not a file: {artifact}")
        subjects.append(
            {
                "name": name,
                "digest": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
            }
        )
    if not subjects:
        raise ValueError("at least one --artifact NAME=PATH is required")
    sbom = canonical_json(spdx_document(metadata, arguments.source_sha256))
    sbom_path = arguments.output / "runtime.spdx.json"
    sbom_path.write_bytes(sbom)
    provenance = canonical_json(
        provenance_document(
            metadata,
            arguments.source_sha256,
            hashlib.sha256(sbom).hexdigest(),
            subjects,
            ["cargo metadata --locked --format-version 1"],
        )
    )
    (arguments.output / "runtime.provenance.json").write_bytes(provenance)
    print(
        "runtime-metadata=ok "
        f"sbom_sha256={hashlib.sha256(sbom).hexdigest()} "
        f"provenance_sha256={hashlib.sha256(provenance).hexdigest()} "
        "signed=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
