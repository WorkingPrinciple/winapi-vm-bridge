#!/usr/bin/env python3
"""Build deterministic native and managed scalar VM acceptance payloads."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/acceptance/windows-vm"
RUNTIME = ROOT / "out/acceptance/windows-dotnet8-x64"
CACHE = ROOT / "out/runtime-cache"
WHINY = ROOT / "runtime-artifacts/whiny-v0.3.0"
FROZEN = ROOT / "external/whiny/v0.3.0/frozen-bundles"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deterministic_environment() -> dict[str, str]:
    environment = os.environ.copy()
    remap = f"--remap-path-prefix={ROOT}=/workspace"
    environment["RUSTFLAGS"] = " ".join(
        value for value in [environment.get("RUSTFLAGS", ""), remap] if value
    )
    environment["CARGO_INCREMENTAL"] = "0"
    environment["SOURCE_DATE_EPOCH"] = "0"
    return environment


def require_hash(path: Path, expected: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise RuntimeError(f"hash mismatch {path}: expected={expected} actual={actual}")


def write_zip(path: Path, files: dict[str, Path]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.unlink(missing_ok=True)
    with zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, source in sorted(files.items()):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    temporary.replace(path)


def file_manifest(files: dict[str, tuple[str, Path]]) -> list[dict[str, str]]:
    return [
        {"key": key, "relativePath": relative, "sha256": sha256(path)}
        for key, (relative, path) in sorted(files.items())
    ]


def main() -> int:
    subprocess.run([str(ROOT / "setup/provision_windows_dotnet_runtime.py")], check=True)
    subprocess.run([str(ROOT / "native/managed-host/build-and-test.sh")], check=True)
    environment = deterministic_environment()
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "wvb-managed-e2e",
            "-p",
            "wvb-native-e2e",
        ],
        check=True,
        cwd=ROOT,
        env=environment,
    )
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--target",
            "x86_64-pc-windows-gnu",
            "-p",
            "wvb-managed-e2e",
            "-p",
            "wvb-native-e2e",
        ],
        check=True,
        cwd=ROOT,
        env=environment,
    )

    managed_admission = json.loads(
        (WHINY / "managed-scalar/execution-admission.json").read_text()
    )
    native_admission = json.loads(
        (WHINY / "native-scalar/execution-admission.json").read_text()
    )
    managed_expected = {
        entry["kind"]: entry["sha256"] for entry in managed_admission["files"]
    }
    native_expected = {
        entry["kind"]: entry["sha256"] for entry in native_admission["files"]
    }
    require_hash(
        WHINY / "managed-scalar/ExampleManagedMath.WhinyDispatcher.dll",
        managed_expected["dispatcher"],
    )
    require_hash(
        WHINY / "managed-scalar/Example.ManagedMath.dll",
        managed_expected["target"],
    )
    require_hash(
        WHINY / "native-scalar/dispatcher.dll",
        native_expected["dispatcher"],
    )
    require_hash(
        WHINY / "native-scalar/target/native_math.dll",
        native_expected["target"],
    )

    windows = ROOT / "target/x86_64-pc-windows-gnu/release"
    managed_files = {
        "Broker": ("wvb-managed-e2e.exe", windows / "wvb-managed-e2e.exe"),
        "NativeHost": (
            "wvb_managed_host.dll",
            ROOT / "out/managed-host/a/wvb_managed_host.dll",
        ),
        "Dispatcher": (
            "ExampleManagedMath.WhinyDispatcher.dll",
            WHINY / "managed-scalar/ExampleManagedMath.WhinyDispatcher.dll",
        ),
        "RuntimeConfig": (
            "ExampleManagedMath.WhinyDispatcher.runtimeconfig.json",
            WHINY
            / "managed-scalar/ExampleManagedMath.WhinyDispatcher.runtimeconfig.json",
        ),
        "Target": (
            "Example.ManagedMath.dll",
            WHINY / "managed-scalar/Example.ManagedMath.dll",
        ),
        "Contract": (
            "contract.canonical.json",
            FROZEN / "managed-scalar/contract.canonical.json",
        ),
    }
    native_files = {
        "Broker": ("wvb-native-e2e.exe", windows / "wvb-native-e2e.exe"),
        "Dispatcher": ("dispatcher.dll", WHINY / "native-scalar/dispatcher.dll"),
        "Target": (
            "target/native_math.dll",
            WHINY / "native-scalar/target/native_math.dll",
        ),
        "Contract": (
            "contract.canonical.json",
            FROZEN / "native-scalar/contract.canonical.json",
        ),
    }
    for _, path in [*managed_files.values(), *native_files.values()]:
        if not path.is_file():
            raise RuntimeError(f"required acceptance input is missing: {path}")

    OUT.mkdir(parents=True, exist_ok=True)
    managed_zip = OUT / "managed-payload.zip"
    native_zip = OUT / "native-payload.zip"
    write_zip(
        managed_zip,
        {relative: path for relative, path in managed_files.values()},
    )
    write_zip(
        native_zip,
        {relative: path for relative, path in native_files.values()},
    )

    runtime_zip = CACHE / "dotnet-runtime-8.0.32-win-x64.zip"
    nethost_package = CACHE / "microsoft.netcore.app.host.win-x64.8.0.32.nupkg"
    hostfxr = RUNTIME / "dotnet/host/fxr/8.0.32/hostfxr.dll"
    nethost = RUNTIME / "host/nethost.dll"
    package = {
        "schema": "wvb.windows-vm-scalar-package.v1",
        "managed": {
            "profile": "managed-scalar",
            "bundleSha256": managed_admission["sourceBundleSha256"],
            "contractSha256": managed_admission["contractSha256"],
            "operationId": 1,
            "requestSchemaId": 0x3000_0001,
            "responseSchemaId": 0x3000_0002,
            "runtimePackageSha256": sha256(runtime_zip),
            "nethostPackageSha256": sha256(nethost_package),
            "hostfxrSha256": sha256(hostfxr),
            "nethostSha256": sha256(nethost),
            "payloadZipSha256": sha256(managed_zip),
            "files": file_manifest(managed_files),
        },
        "native": {
            "profile": "native-scalar",
            "bundleSha256": native_admission["sourceBundleSha256"],
            "contractSha256": native_admission["contractSha256"],
            "operationId": 1,
            "requestSchemaId": 0x1000_0001,
            "responseSchemaId": 0x1000_0002,
            "payloadZipSha256": sha256(native_zip),
            "files": file_manifest(native_files),
        },
    }
    manifest = OUT / "acceptance-package.json"
    manifest.write_text(
        json.dumps(package, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    shutil.copyfile(
        ROOT / "target/release/wvb-managed-e2e",
        OUT / "wvb-managed-e2e",
    )
    (OUT / "wvb-managed-e2e").chmod(0o755)
    shutil.copyfile(
        ROOT / "target/release/wvb-native-e2e",
        OUT / "wvb-native-e2e",
    )
    (OUT / "wvb-native-e2e").chmod(0o755)
    print(
        f"windows-vm-acceptance=ok manifest={manifest} "
        f"manifestSha256={sha256(manifest)} managedZip={sha256(managed_zip)} "
        f"nativeZip={sha256(native_zip)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
