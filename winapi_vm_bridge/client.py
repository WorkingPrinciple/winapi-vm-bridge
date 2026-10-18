from __future__ import annotations

import socket

from .protocol import PING, decode_json, encode_json, receive_exact, receive_frame, send_frame, valid_capability


def call(host: str, port: int, capability: str, adapter: str, operation: str,
         arguments: object, timeout: float = 15.0) -> object:
    if not valid_capability(capability):
        raise ValueError("invalid capability")
    request = {"adapter": adapter, "operation": operation, "arguments": arguments}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(capability.encode("ascii"))
        if receive_exact(sock, 1) != b"\x01":
            raise PermissionError("broker rejected capability")
        send_frame(sock, PING, encode_json(request))
        kind, payload = receive_frame(sock)
        if kind != PING + 1:
            raise ValueError("unexpected response type")
        return decode_json(payload)

