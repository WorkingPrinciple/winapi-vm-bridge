#!/usr/bin/env python3
"""Provision the pinned Windows .NET runtime into the ignored acceptance area."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "setup/runtime-pins/windows-dotnet8-x64.json"
DEFAULT_CACHE = REPO_ROOT / "out/runtime-cache"
ACCEPTANCE_ROOT = (REPO_ROOT / "out/acceptance").resolve()
OUT_ROOT = (REPO_ROOT / "out").resolve()


def digest(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def verify_digest(path: Path, algorithm: str, expected: str) -> None:
    observed = digest(path, algorithm)
    if observed != expected:
        raise RuntimeError(
            f"{path.name} {algorithm} mismatch: expected {expected}, observed {observed}"
        )


def download(url: str, destination: Path) -> None:
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url, headers={"User-Agent": "winapi-vm-bridge-runtime-provisioner/1"}
    )
    with tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                shutil.copyfileobj(response, temporary)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    temporary_path.replace(destination)


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = []
    for member in archive.infolist():
        path = PurePosixPath(member.filename)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"unsafe archive member {member.filename}")
        members.append(member)
    return members


def extract_runtime(package: Path, destination: Path) -> None:
    with zipfile.ZipFile(package) as archive:
        archive.extractall(destination, members=safe_members(archive))


def extract_host_package(
    package: Path, destination: Path, nethost_package_path: str
) -> None:
    with zipfile.ZipFile(package) as archive:
        members = {member.filename: member for member in safe_members(archive)}
        selected = {
            nethost_package_path: destination / "nethost.dll",
            "LICENSE.TXT": destination / "LICENSE.TXT",
        }
        for source, target in selected.items():
            if source not in members:
                raise RuntimeError(f"required NuGet member is missing: {source}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(members[source]) as input_stream, target.open(
                "wb"
            ) as output_stream:
                shutil.copyfileobj(input_stream, output_stream)


def verify_nuget_signature(dotnet: str, package: Path) -> None:
    completed = subprocess.run(
        [dotnet, "nuget", "verify", str(package), "--all"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"NuGet signature verification failed: {completed.stderr}")
    required = (
        "Signature type: Author",
        "CN=Microsoft Corporation",
        "Signature type: Repository",
        "CN=NuGet.org Repository by Microsoft",
    )
    if any(value not in completed.stdout for value in required):
        raise RuntimeError("NuGet signature identities did not match the pin policy")


def require_acceptance_path(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == ACCEPTANCE_ROOT or ACCEPTANCE_ROOT not in resolved.parents:
        raise RuntimeError(f"output must be a child of {ACCEPTANCE_ROOT}")
    return resolved


def require_cache_path(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == OUT_ROOT or OUT_ROOT not in resolved.parents:
        raise RuntimeError(f"cache must be a child of {OUT_ROOT}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument(
        "--out",
        type=Path,
        default=ACCEPTANCE_ROOT / "windows-dotnet8-x64",
    )
    parser.add_argument("--dotnet", default="dotnet")
    arguments = parser.parse_args()

    manifest = json.loads(arguments.manifest.read_text(encoding="utf-8"))
    output = require_acceptance_path(arguments.out)
    cache = require_cache_path(arguments.cache)
    runtime = manifest["runtime"]
    host_package = manifest["nethostPackage"]
    runtime_package = cache / runtime["fileName"]
    nethost_package = cache / host_package["fileName"]

    download(runtime["url"], runtime_package)
    download(host_package["url"], nethost_package)
    verify_digest(runtime_package, "sha256", runtime["sha256"])
    verify_digest(runtime_package, "sha512", runtime["sha512"])
    verify_digest(nethost_package, "sha256", host_package["sha256"])
    verify_digest(nethost_package, "sha512", host_package["sha512"])
    verify_nuget_signature(arguments.dotnet, nethost_package)

    if output.exists():
        shutil.rmtree(output)
    (output / "dotnet").mkdir(parents=True)
    (output / "host").mkdir(parents=True)
    extract_runtime(runtime_package, output / "dotnet")
    extract_host_package(
        nethost_package,
        output / "host",
        manifest["files"]["nethost"]["packagePath"],
    )
    for file_pin in manifest["files"].values():
        verify_digest(output / file_pin["path"], "sha256", file_pin["sha256"])

    receipt = {
        "schemaVersion": 1,
        "version": manifest["version"],
        "rid": manifest["rid"],
        "sourceManifest": str(arguments.manifest.resolve()),
        "runtime": {
            "url": runtime["url"],
            "sha256": runtime["sha256"],
            "sha512": runtime["sha512"],
        },
        "nethostPackage": {
            "url": host_package["url"],
            "sha256": host_package["sha256"],
            "sha512": host_package["sha512"],
            "signatureVerified": True,
            "licenseExpression": host_package["licenseExpression"],
        },
        "files": manifest["files"],
    }
    (output / "provisioned.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"windows-dotnet-runtime={manifest['version']} out={output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"provision_windows_dotnet_runtime: {error}", file=sys.stderr)
        raise SystemExit(2)
