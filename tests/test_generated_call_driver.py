import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from setup.run_generated_call import run_call


class GeneratedCallDriverTests(unittest.TestCase):
    def test_one_call_exact_result_and_no_implicit_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "call.json"
            config.write_text(json.dumps({"connect_timeout_ms": 1000, "call_timeout_ms": 1000}))
            response = root / "response.bin"
            request = root / "request.bin"
            request.write_bytes(b"")

            def invoke(command, **kwargs):
                self.assertEqual(command[1], "call")
                self.assertEqual(kwargs["timeout"], 12)
                response.write_bytes((1234).to_bytes(4, "little"))
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "event": "result", "dispatch_status": 0, "response_bytes": 4,
                }), "")

            with patch("setup.run_generated_call.subprocess.run", side_effect=invoke) as run:
                self.assertEqual(run_call(Path("/wvb"), config, request, response, 1234)["observed_u32"], 1234)
                run.assert_called_once()
                with self.assertRaises(ValueError):
                    run_call(Path("/wvb"), config, request, response)
                run.assert_called_once()

    def test_timeout_never_reexecutes_or_infers_guest_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "call.json"
            config.write_text(json.dumps({"connect_timeout_ms": 1000, "call_timeout_ms": 1000}))
            with patch("setup.run_generated_call.subprocess.run",
                       side_effect=subprocess.TimeoutExpired(["wvb"], 12)) as run:
                with self.assertRaisesRegex(RuntimeError, "guest completion unknown"):
                    run_call(Path("/wvb"), config, root / "request", root / "response")
                run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
