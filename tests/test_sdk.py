import json
import tempfile
import unittest
from pathlib import Path

from sdk.generate import generate, validate
from winapi_vm_bridge.client import call
from winapi_vm_bridge.server import serve
import secrets
import socket
import threading
import time


class GeneratorTests(unittest.TestCase):
    def test_example_generates_review_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            generate(Path("examples/example-math/adapter.json"), out)
            target = out / "example-math"
            self.assertTrue((target / "contract.json").is_file())
            self.assertIn("ExampleAdd", (target / "dispatch.generated.cpp").read_text())
            self.assertIn("real application operation", (target / "CHECKLIST.md").read_text())

    def test_unknown_top_level_field_rejected(self):
        data = json.loads(Path("examples/example-math/adapter.json").read_text())
        data["unsafeDllPath"] = "anything.dll"
        with self.assertRaises(ValueError):
            validate(data)

    def test_real_authenticated_round_trip(self):
        capability = secrets.token_hex(32)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        thread = threading.Thread(
            target=serve, args=("127.0.0.1", port, capability), daemon=True)
        thread.start()
        for _ in range(100):
            try:
                result = call("127.0.0.1", port, capability, "core", "ping", {})
                break
            except ConnectionRefusedError:
                time.sleep(0.01)
                continue
        else:
            self.fail("broker did not start")
        self.assertTrue(result["ok"])
        with self.assertRaises(PermissionError):
            call("127.0.0.1", port, "0" * 64, "core", "ping", {})

    def test_unbounded_buffer_rejected(self):
        data = json.loads(Path("examples/example-math/adapter.json").read_text())
        data["operations"]["Add"]["parameters"][0] = {
            "name": "input", "type": "bytes", "direction": "in"
        }
        with self.assertRaises(ValueError):
            validate(data)


if __name__ == "__main__":
    unittest.main()
