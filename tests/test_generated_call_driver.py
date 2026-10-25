import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from setup.run_generated_call import run_call, run_proxy_call


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

    def test_proxy_call_uses_original_export_caller_and_one_paired_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "system.reg").write_text("owned prefix")
            contract = root / "contract.json"
            contract.write_bytes(b"contract")
            key = root / "client.key"
            key.write_bytes(b"\x07" * 32)
            key.chmod(0o600)
            proxy = root / "proxy.dll"
            proxy.write_bytes(b"generated proxy")
            contract_hash = hashlib.sha256(contract.read_bytes()).digest()
            proxy_hash = hashlib.sha256(proxy.read_bytes()).hexdigest()
            config = root / "call.json"
            config.write_text(json.dumps({
                "contract_path": str(contract), "contract_sha256": list(contract_hash),
                "private_key_path": str(key), "address": "192.168.64.4:47963",
                "broker_public_key": [1] * 32, "actor_id": [2] * 16,
                "client_instance": [3] * 16, "build_fingerprint": [4] * 32,
                "connect_timeout_ms": 5000, "call_timeout_ms": 5000,
            }))
            response, trace = root / "response.bin", root / "trace.jsonl"

            def invoke(command, **kwargs):
                self.assertEqual(command[:2], ["/wine", str(root / "caller.exe")])
                self.assertIn("Z:" + str(key).replace("/", "\\"), command)
                self.assertNotIn(key.read_bytes().hex(), command)
                self.assertEqual(kwargs["timeout"], 60)
                rows = []
                for index, kind in enumerate(("run_start", "entry", "return", "run_end")):
                    rows.append({
                        "kind": kind, "sequence": index, "route": "remote",
                        "proxy_artifact_sha256": proxy_hash,
                        "contract_sha256": contract_hash.hex(), "process_id": 32,
                        "target": "kernel32.dll!GetCurrentProcessId",
                        "call_id": "1", "status": "ok", "complete": True,
                    })
                trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
                return subprocess.CompletedProcess(command, 0,
                    "pid-proxy result=5932 expected=5932 caller_pid=32\r\n", "")

            environment = {"WINEPREFIX": str(root), "WINEDLLPATH": str(root / "pair")}
            with patch.dict("os.environ", environment, clear=True), \
                    patch("setup.run_generated_call.subprocess.run", side_effect=invoke) as run:
                result = run_proxy_call(Path("/wine"), root / "caller.exe", proxy,
                                        config, response, trace, 5932)
                self.assertEqual(result["route"], "generated-proxy")
                self.assertEqual(response.read_bytes(), b"\x2c\x17\x00\x00")
                self.assertEqual(response.stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(ValueError, "never reuse"):
                    run_proxy_call(Path("/wine"), root / "caller.exe", proxy,
                                   config, response, trace, 5932)
                run.assert_called_once()

                trace = root / "incomplete-trace.jsonl"

                def incomplete(command, **kwargs):
                    result = invoke(command, **kwargs)
                    rows = [json.loads(line) for line in trace.read_text().splitlines()]
                    rows[-1]["complete"] = False
                    trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
                    return result

                run.side_effect = incomplete
                with self.assertRaisesRegex(ValueError, "does not prove one completed"):
                    run_proxy_call(Path("/wine"), root / "caller.exe", proxy,
                                   config, root / "incomplete-response.bin", trace, 5932)
                self.assertEqual((root / "incomplete-response.bin").stat().st_size, 0)
                self.assertEqual(run.call_count, 2)

    def test_proxy_mode_never_bootstraps_or_launches_an_unprepared_prefix(self):
        with patch.dict("os.environ", {}, clear=True), \
                patch("setup.run_generated_call.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "prepare an explicit Wine prefix"):
                run_proxy_call(Path("/wine"), Path("/caller"), Path("/proxy"),
                               Path("/config"), Path("/response"), Path("/trace"), 5932)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
