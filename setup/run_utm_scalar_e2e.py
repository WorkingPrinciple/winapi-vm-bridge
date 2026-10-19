#!/usr/bin/env python3
"""Run one frozen scalar encrypted round trip against the exact UTM guest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

try:
    from .run_utm_deploy import pull, require_target
except ImportError:
    from run_utm_deploy import pull, require_target


DEFAULT_UTMCTL = "/Applications/UTM.app/Contents/MacOS/utmctl"
DEFAULT_VM = "Whiny-Windows11-x64"
DEFAULT_UUID = "F659FCF2-AC83-4072-86A6-F7538781A1FC"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def x25519_key_pair() -> tuple[str, str]:
    private_der = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    public_der = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private_der,
        check=True,
        capture_output=True,
    ).stdout
    if len(private_der) < 32 or len(public_der) < 32:
        raise RuntimeError("OpenSSL returned malformed X25519 keys")
    return private_der[-32:].hex(), public_der[-32:].hex()


def pull_required(utmctl: str, vm: str, path: str) -> bytes:
    for _ in range(20):
        value = pull(utmctl, vm, path)
        if value is not None:
            return value
        time.sleep(0.5)
    raise RuntimeError(f"guest acceptance evidence is unavailable: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["native", "managed"], required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--address")
    parser.add_argument("--sudo-client", action="store_true")
    parser.add_argument(
        "--client-mode", choices=["positive", "schema-negative"], default="positive"
    )
    parser.add_argument("--root")
    parser.add_argument("--utmctl", default=DEFAULT_UTMCTL)
    parser.add_argument("--vm", default=DEFAULT_VM)
    parser.add_argument("--expected-uuid", default=DEFAULT_UUID)
    arguments = parser.parse_args()

    require_target(arguments.utmctl, arguments.vm, arguments.expected_uuid)
    document = json.loads(arguments.manifest.read_text(encoding="utf-8"))
    profile = document[arguments.profile]
    address = arguments.address or (
        "192.168.64.4:47960"
        if arguments.profile == "native"
        else "192.168.64.4:47961"
    )
    root = arguments.root or (
        r"C:\WvbAcceptance\native-scalar"
        if arguments.profile == "native"
        else r"C:\WvbAcceptance\canonical-runtime"
    )
    guest_config = root + r"\e2e-config.json"
    guest_log = root + r"\server.log"
    guest_exit = root + r"\server.exit"
    runner = root + r"\run-server.cmd"
    broker_private, broker_public = x25519_key_pair()
    client_private, client_public = x25519_key_pair()
    environment = os.environ.copy()
    environment.update(
        {
            "WVB_TEST_BROKER_PRIVATE": broker_private,
            "WVB_TEST_BROKER_PUBLIC": broker_public,
            "WVB_TEST_CLIENT_PRIVATE": client_private,
            "WVB_TEST_CLIENT_PUBLIC": client_public,
        }
    )
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        config = pull(arguments.utmctl, arguments.vm, guest_config)
        if config is None:
            raise RuntimeError("guest acceptance configuration is unavailable")
        config_path = temporary_root / "e2e-config.json"
        config_path.write_bytes(config)
        parsed = json.loads(config.decode("utf-8-sig"))
        if parsed["address"] != address or parsed["adapterHash"] != profile[
            "contractSha256"
        ]:
            raise RuntimeError("guest config identity mismatch")

        server_command = [
                arguments.utmctl,
                "exec",
                arguments.vm,
                "--env",
                f"WVB_TEST_BROKER_PRIVATE={broker_private}",
                "--env",
                f"WVB_TEST_CLIENT_PUBLIC={client_public}",
        ]
        if arguments.client_mode == "schema-negative":
            server_command.extend(["--env", "WVB_EXPECT_SCHEMA_NEGATIVE=1"])
        server_command.extend(
            [
                "--cmd",
                r"C:\Windows\System32\cmd.exe",
                "/d",
                "/c",
                runner,
            ]
        )
        server = subprocess.Popen(
            server_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(3)
            if not arguments.sudo_client:
                host, port_text = address.rsplit(":", 1)
                host = host.strip("[]")
                for _ in range(30):
                    try:
                        with socket.create_connection((host, int(port_text)), timeout=1):
                            break
                    except OSError:
                        time.sleep(1)
                else:
                    raise RuntimeError("guest broker TCP route did not become reachable")
            mode = (
                "client"
                if arguments.client_mode == "positive"
                else "client-schema-negative"
            )
            client_command = [str(arguments.client), mode, str(config_path)]
            if arguments.sudo_client:
                client_command = ["sudo", "-n", "-E", *client_command]
            client = None
            started_at = datetime.now(UTC)
            started_monotonic = time.perf_counter_ns()
            for _ in range(15):
                client = subprocess.run(
                    client_command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=30,
                )
                if client.returncode == 0:
                    break
                diagnostic = client.stdout + client.stderr
                retryable = (
                    "HostUnreachable",
                    "Connection refused",
                    "TimedOut",
                    "timed out",
                )
                if not any(value in diagnostic for value in retryable):
                    break
                time.sleep(2)
            completed_monotonic = time.perf_counter_ns()
            completed_at = datetime.now(UTC)
            assert client is not None
            if client.returncode != 0:
                raise RuntimeError(
                    f"{arguments.profile} client failed exit={client.returncode}: "
                    f"{client.stdout}{client.stderr}"
                )
            try:
                server_status = server.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("guest broker did not terminate") from error
            if server_status != 0:
                output = server.stdout.read() if server.stdout else ""
                raise RuntimeError(
                    f"guest broker launcher failed exit={server_status}: {output}"
                )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)

        log = pull_required(arguments.utmctl, arguments.vm, guest_log)
        exit_code = pull_required(arguments.utmctl, arguments.vm, guest_exit)
        deployment = pull_required(
            arguments.utmctl, arguments.vm, root + r"\deployment.json"
        )
        if exit_code.decode("ascii", errors="ignore").strip() != "0":
            raise RuntimeError(f"guest broker exit evidence: {exit_code!r}")
        deployment_value = json.loads(deployment.decode("utf-8-sig"))
        receipt = {
            "schema": "wvb.windows-vm-scalar-acceptance.v1",
            "profile": arguments.profile,
            "status": "PASS",
            "vm": arguments.vm,
            "vmUuid": arguments.expected_uuid,
            "address": address,
            "bundleSha256": profile["bundleSha256"],
            "contractSha256": profile["contractSha256"],
            "operationId": profile["operationId"],
            "requestSchemaId": profile["requestSchemaId"],
            "responseSchemaId": profile["responseSchemaId"],
            "assertion": (
                "result=42"
                if arguments.client_mode == "positive"
                else "request-schema-rejected"
            ),
            "startedAt": started_at.isoformat(),
            "completedAt": completed_at.isoformat(),
            "elapsedNs": completed_monotonic - started_monotonic,
            "manifestSha256": sha256(arguments.manifest),
            "clientSha256": sha256(arguments.client),
            "clientStdout": client.stdout.strip(),
            "serverLogSha256": hashlib.sha256(log).hexdigest(),
            "serverLog": log.decode("utf-8-sig", errors="replace").strip(),
            "deploymentSha256": hashlib.sha256(deployment).hexdigest(),
            "deployment": deployment_value,
            "brokerPublicKeySha256": hashlib.sha256(
                bytes.fromhex(broker_public)
            ).hexdigest(),
            "clientPublicKeySha256": hashlib.sha256(
                bytes.fromhex(client_public)
            ).hexdigest(),
        }
        arguments.receipt.parent.mkdir(parents=True, exist_ok=True)
        arguments.receipt.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    print(
        f"utm-scalar-e2e=ok profile={arguments.profile} "
        f"receipt={arguments.receipt}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_utm_scalar_e2e: {error}", file=sys.stderr)
        raise SystemExit(2)
