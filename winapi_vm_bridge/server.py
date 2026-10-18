from __future__ import annotations

import argparse
import hmac
import json
import socket
from pathlib import Path

from .protocol import PING, decode_json, encode_json, receive_exact, receive_frame, send_frame, valid_capability


def handle(connection: socket.socket, capability: str) -> None:
    presented = receive_exact(connection, 64)
    accepted = hmac.compare_digest(presented, capability.encode("ascii"))
    connection.sendall(b"\x01" if accepted else b"\x00")
    if not accepted:
        return
    kind, payload = receive_frame(connection)
    if kind != PING:
        send_frame(connection, kind + 1, encode_json({"ok": False, "error": "unsupported operation type"}))
        return
    request = decode_json(payload)
    if not isinstance(request, dict) or request.get("adapter") != "core" or request.get("operation") != "ping":
        result = {"ok": False, "error": "adapter or operation not installed"}
    else:
        result = {"ok": True, "adapter": "core", "operation": "ping", "broker": "windows"}
    send_frame(connection, kind + 1, encode_json(result))


def serve(host: str, port: int, capability: str) -> None:
    if not valid_capability(capability):
        raise ValueError("invalid capability")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(15)
                try:
                    handle(connection, capability)
                except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
                    pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=47801)
    parser.add_argument("--capability-file", type=Path, required=True)
    args = parser.parse_args()
    capability = args.capability_file.read_text().strip()
    serve(args.host, args.port, capability)


if __name__ == "__main__":
    main()

