#!/usr/bin/env python3
"""Run the bounded CrossOver broker and native macOS client acceptance pair."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from queue import Empty, Queue


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
    parser.add_argument("--wine", required=True)
    parser.add_argument("--bottle", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--windows-config", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
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

    server = subprocess.Popen(
        [
            arguments.wine,
            "--bottle",
            arguments.bottle,
            arguments.server,
            "server",
            arguments.windows_config,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=environment,
    )
    lines: Queue[str] = Queue()

    def read_server() -> None:
        assert server.stdout is not None
        for line in server.stdout:
            print(line, end="")
            lines.put(line)

    reader = threading.Thread(target=read_server, daemon=True)
    reader.start()
    try:
        for _ in range(30):
            try:
                line = lines.get(timeout=1)
            except Empty:
                if server.poll() is not None:
                    raise RuntimeError(
                        f"Windows managed broker exited early with {server.returncode}"
                    )
                continue
            if line.startswith("managed-broker-ready="):
                break
        else:
            raise RuntimeError("Windows managed broker readiness timed out")

        client = subprocess.run(
            [arguments.client, "client", arguments.config],
            check=False,
            text=True,
            env=environment,
        )
        if client.returncode != 0:
            raise RuntimeError(f"managed client failed with {client.returncode}")
        server_status = server.wait(timeout=20)
        if server_status != 0:
            raise RuntimeError(f"managed broker failed with {server_status}")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    print("managed-encrypted-cross-platform=ok result=42")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_cross_platform_managed_e2e: {error}", file=sys.stderr)
        raise SystemExit(2)
