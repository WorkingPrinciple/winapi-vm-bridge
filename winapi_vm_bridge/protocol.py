from __future__ import annotations

import json
import socket
import struct

MAGIC = 0x58445358
HEADER = struct.Struct("<IHH")
MAX_PAYLOAD = 65535
PING = 0x101


def valid_capability(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


def receive_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock: socket.socket, kind: int, payload: bytes) -> None:
    if not 0 <= kind <= 0xFFFF or len(payload) > MAX_PAYLOAD:
        raise ValueError("invalid frame")
    sock.sendall(HEADER.pack(MAGIC, kind, len(payload)) + payload)


def receive_frame(sock: socket.socket) -> tuple[int, bytes]:
    magic, kind, size = HEADER.unpack(receive_exact(sock, HEADER.size))
    if magic != MAGIC:
        raise ValueError("invalid frame magic")
    return kind, receive_exact(sock, size)


def encode_json(value: object) -> bytes:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("JSON payload too large")
    return payload


def decode_json(payload: bytes) -> object:
    return json.loads(payload.decode("utf-8"))

