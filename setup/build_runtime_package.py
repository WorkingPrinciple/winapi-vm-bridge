#!/usr/bin/env python3
"""Build deterministic unsigned runtime archives and external provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

try:
    from .generate_runtime_metadata import (
        canonical_json,
        provenance_document,
        spdx_document,
    )
except ImportError:
    from generate_runtime_metadata import canonical_json, provenance_document, spdx_document


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_file(source: Path, destination: Path, executable: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def add_tree(archive: tarfile.TarFile, root: Path, prefix: str) -> None:
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = archive.gettarinfo(str(path), f"{prefix}/{relative}")
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        if path.is_file():
            with path.open("rb") as source:
                archive.addfile(info, source)
        else:
            archive.addfile(info)


def cargo_metadata() -> dict[str, object]:
    return json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )

def deterministic_environment() -> dict[str, str]:
    environment = os.environ.copy()
    root = str(Path.cwd().resolve())
    remap = f"--remap-path-prefix={root}=/workspace"
    environment["RUSTFLAGS"] = " ".join(
        value for value in [environment.get("RUSTFLAGS", ""), remap] if value
    )
    environment["CARGO_INCREMENTAL"] = "0"
    environment["SOURCE_DATE_EPOCH"] = "0"
    return environment


def build_macos_provisioner(destination: Path) -> None:
    subprocess.run(
        [
            "clang", "-std=c17", "-Wall", "-Wextra", "-Werror", "-O2",
            "-I", "native/macos-keychain/include",
            "native/macos-keychain/src/wvb_keychain.c",
            "native/macos-keychain/src/wvb_provision.c",
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(destination),
        ],
        check=True,
    )
    destination.chmod(0o755)


def build(
    platform: str, source_sha256: str, output: Path, variant: str | None = None
) -> tuple[Path, Path]:
    metadata = cargo_metadata()
    version = next(
        package["version"]
        for package in metadata["packages"]
        if package["name"] == "wvb-runtime"
    )
    target = None if platform == "macos" else "x86_64-pc-windows-gnu"
    command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "-p",
        "wvb-client-ffi",
        "--features",
        "wvb-client-ffi/cli,wvb-runtime/legacy-admin",
        "-p",
        "wvb-runtime",
        "-p",
        "wvb-package",
        "-p",
        "wvb-receipt",
    ]
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "-p", "wvb-package"],
        check=True,
        env=deterministic_environment(),
    )
    if target:
        command.extend(["--target", target])
    subprocess.run(command, check=True, env=deterministic_environment())
    build_root = Path("target") / (target or "release")
    if target:
        build_root /= "release"

    with tempfile.TemporaryDirectory() as temporary:
        release_name = f"winapi-vm-bridge-{platform}-{version}"
        package_version = f"{version}-{platform}"
        if variant:
            release_name += f"-{variant}"
            package_version += f"-{variant}"
        package = Path(temporary) / release_name
        payload = package / "payload"
        lifecycle = package / "bin"
        suffix = ".exe" if platform == "windows" else ""
        for binary in ["wvb", "wvb-runtime", "wvb-package", "wvb-receipt"]:
            source = build_root / f"{binary}{suffix}"
            copy_file(source, payload / "bin" / source.name, True)
            if binary == "wvb-package":
                copy_file(source, lifecycle / source.name, True)
        if platform == "macos":
            build_macos_provisioner(payload / "bin/wvb-provision")
        shutil.copytree(
            "external/whiny/v0.3.0",
            payload / "share/whiny/v0.3.0",
            ignore=shutil.ignore_patterns("bin", "obj"),
        )
        shutil.copytree(
            "runtime-artifacts/whiny-v0.3.0",
            payload / "share/runtime-artifacts/whiny-v0.3.0",
        )

        sbom = canonical_json(spdx_document(metadata, source_sha256))
        sbom_path = payload / "share/runtime.spdx.json"
        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        sbom_path.write_bytes(sbom)

        files = []
        for path in sorted(payload.rglob("*"), key=lambda value: value.as_posix()):
            if path.is_file():
                relative = path.relative_to(payload).as_posix()
                files.append(
                    {
                        "relative_path": relative,
                        "sha256": list(hashlib.sha256(path.read_bytes()).digest()),
                        "executable": relative.startswith("bin/"),
                    }
                )
        manifest = {
            "identifier": "winapi-vm-bridge.runtime-package.v1",
            "major": 1,
            "package_version": package_version,
            "source_sha256": list(bytes.fromhex(source_sha256)),
            "sbom_sha256": list(hashlib.sha256(sbom).digest()),
            "files": files,
        }
        manifest_path = package / "runtime-package.json"
        manifest_path.write_bytes(canonical_json(manifest))
        release_files = []
        for path in sorted(package.rglob("*"), key=lambda value: value.as_posix()):
            if path.is_file():
                release_files.append(
                    {
                        "path": path.relative_to(package).as_posix(),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        (package / "release-manifest.json").write_bytes(
            canonical_json(
                {
                    "schema": "winapi-vm-bridge.release-envelope.v1",
                    "platform": platform,
                    "version": version,
                    "files": release_files,
                }
            )
        )
        subprocess.run(
            [
                str(Path("target/release/wvb-package")),
                "verify",
                "--source",
                str(payload),
                "--manifest",
                str(manifest_path),
            ],
            check=True,
        )

        output.mkdir(parents=True, exist_ok=True)
        archive_path = output / f"{release_name}.tar"
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
            add_tree(archive, package, package.name)

    provenance = provenance_document(
        metadata,
        source_sha256,
        hashlib.sha256(sbom).hexdigest(),
        [{"name": archive_path.name, "digest": {"sha256": sha256(archive_path)}}],
        [
            "cargo build --release --locked -p wvb-package",
            " ".join(command),
            "wvb-package verify --source payload --manifest runtime-package.json",
        ],
    )
    provenance_path = archive_path.with_suffix(".provenance.json")
    provenance_path.write_bytes(canonical_json(provenance))
    return archive_path, provenance_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=["macos", "windows"], required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant")
    arguments = parser.parse_args()
    if len(arguments.source_sha256) != 64:
        raise ValueError("source SHA-256 must be 64 hexadecimal characters")
    if arguments.variant and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]*", arguments.variant
    ):
        raise ValueError("variant must use lowercase alphanumerics, dots or hyphens")
    archive, provenance = build(
        arguments.platform,
        arguments.source_sha256,
        arguments.output,
        arguments.variant,
    )
    print(
        f"runtime-package=ok archive={archive} sha256={sha256(archive)} "
        f"provenance={provenance} signed=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
