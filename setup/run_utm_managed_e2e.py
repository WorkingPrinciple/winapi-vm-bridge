#!/usr/bin/env python3
"""Run the managed canonical client against the isolated Windows-RPC VM broker."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--utmctl", default="/Applications/UTM.app/Contents/MacOS/utmctl")
    parser.add_argument("--vm", required=True)
    parser.add_argument("--windows-runner", required=True)
    parser.add_argument("--windows-log", required=True)
    parser.add_argument("--windows-exit", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()

    broker_private, broker_public = x25519_key_pair()
    client_private, client_public = x25519_key_pair()
    keys = {
        "WVB_TEST_BROKER_PRIVATE": broker_private,
        "WVB_TEST_BROKER_PUBLIC": broker_public,
        "WVB_TEST_CLIENT_PRIVATE": client_private,
        "WVB_TEST_CLIENT_PUBLIC": client_public,
    }
    command = [arguments.utmctl, "exec", arguments.vm]
    for name, value in keys.items():
        command.extend(["--env", f"{name}={value}"])
    command.extend(
        [
            "--cmd",
            r"C:\Windows\System32\cmd.exe",
            "/c",
            arguments.windows_runner,
        ]
    )
    server = subprocess.Popen(command)
    environment = os.environ.copy()
    environment.update(keys)
    try:
        time.sleep(5)
        client = subprocess.run(
            [arguments.client, "client", arguments.config],
            check=False,
            text=True,
            env=environment,
        )
        if client.returncode != 0:
            log = subprocess.run(
                [
                    arguments.utmctl,
                    "file",
                    "pull",
                    arguments.vm,
                    arguments.windows_log,
                ],
                capture_output=True,
                check=False,
            )
            diagnostic = (log.stdout + log.stderr).decode(
                "utf-8-sig", errors="replace"
            )
            raise RuntimeError(
                f"managed client failed with {client.returncode}; broker={diagnostic}"
            )
        for _ in range(20):
            completed = subprocess.run(
                [
                    arguments.utmctl,
                    "file",
                    "pull",
                    arguments.vm,
                    arguments.windows_exit,
                ],
                capture_output=True,
                check=False,
            )
            diagnostic = completed.stdout + completed.stderr
            if b"failed to open file" not in diagnostic:
                status = completed.stdout.decode("utf-8-sig", errors="replace").strip()
                if status != "0":
                    raise RuntimeError(f"Windows VM broker failed with {status}")
                break
            time.sleep(1)
        else:
            raise RuntimeError("Windows VM broker exit receipt timed out")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    print("managed-encrypted-utm=ok result=42")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_utm_managed_e2e: {error}", file=sys.stderr)
        raise SystemExit(2)
