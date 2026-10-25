import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from setup.run_generated_call import run_call, run_pid_demo, run_proxy_call


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
            wine = root / "wine"
            wine.write_bytes(b"selected Calimocho engine")
            wine_hash = hashlib.sha256(wine.read_bytes()).hexdigest()
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
                self.assertEqual(command[:2], [str(wine), str(root / "caller.exe")])
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
                result = run_proxy_call(wine, root / "caller.exe", proxy,
                                        config, response, trace, 5932, wine_hash)
                self.assertEqual(result["route"], "generated-proxy")
                self.assertEqual(response.read_bytes(), b"\x2c\x17\x00\x00")
                self.assertEqual(response.stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(ValueError, "never reuse"):
                    run_proxy_call(wine, root / "caller.exe", proxy,
                                   config, response, trace, 5932, wine_hash)
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
                    run_proxy_call(wine, root / "caller.exe", proxy,
                                   config, root / "incomplete-response.bin", trace, 5932, wine_hash)
                self.assertEqual((root / "incomplete-response.bin").stat().st_size, 0)
                self.assertEqual(run.call_count, 2)

                (root / "system.reg").unlink()
                (root / ".update-timestamp").write_text("completed Wineboot")
                (root / "drive_c/windows/system32").mkdir(parents=True)
                trace = root / "cold-prefix-trace.jsonl"
                run.side_effect = invoke
                self.assertEqual(run_proxy_call(wine, root / "caller.exe", proxy, config,
                                  root / "cold-prefix-response.bin", trace, 5932,
                                  wine_hash)["observed_u32"], 5932)
                self.assertFalse((root / "system.reg").exists())
                self.assertEqual(run.call_count, 3)

    def test_proxy_mode_never_bootstraps_or_launches_an_unprepared_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            wine = Path(directory) / "wine"
            wine.write_bytes(b"selected Calimocho engine")
            with patch.dict("os.environ", {}, clear=True), \
                    patch("setup.run_generated_call.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "prepare an explicit Wine prefix"):
                    run_proxy_call(wine, Path("/caller"), Path("/proxy"),
                                   Path("/config"), Path("/response"), Path("/trace"), 5932,
                                   hashlib.sha256(wine.read_bytes()).hexdigest())
                run.assert_not_called()

    def test_crossover_and_hash_drift_are_rejected_before_launch(self):
        with patch("setup.run_generated_call.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "CrossOver paths"):
                run_proxy_call(Path("/Applications/CrossOver.app/wine"), Path("/caller"),
                               Path("/proxy"), Path("/config"), Path("/response"),
                               Path("/trace"), 5932, "0" * 64)
            with tempfile.TemporaryDirectory() as directory:
                wine = Path(directory) / "wine"
                wine.write_bytes(b"selected Calimocho engine")
                with patch.dict("os.environ", {}, clear=True):
                    with self.assertRaisesRegex(ValueError, "engine hash mismatch"):
                        run_proxy_call(wine, Path("/caller"), Path("/proxy"), Path("/config"),
                                       Path("/response"), Path("/trace"), 5932, "0" * 64)
                with patch.dict("os.environ", {"DYLD_LIBRARY_PATH": "/Applications/CrossOver.app/lib"},
                                clear=True):
                    with self.assertRaisesRegex(ValueError, "CrossOver paths"):
                        run_proxy_call(wine, Path("/caller"), Path("/proxy"), Path("/config"),
                                       Path("/response"), Path("/trace"), 5932, "0" * 64)
                vendor = Path(directory) / "CrossOver.app"
                vendor.mkdir()
                (vendor / "wine").write_bytes(b"vendor engine")
                alias = Path(directory) / "renamed-engine"
                alias.symlink_to(vendor / "wine")
                with self.assertRaisesRegex(ValueError, "CrossOver paths"):
                    run_proxy_call(alias, Path("/caller"), Path("/proxy"), Path("/config"),
                                   Path("/response"), Path("/trace"), 5932, "0" * 64)
            run.assert_not_called()

    def test_one_command_demo_stages_privately_and_always_stops_its_owned_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            install = root / "install"
            (install / "bin").mkdir(parents=True)
            wine, server = install / "bin/wine", install / "bin/wineserver"
            wine.write_bytes(b"selected own engine")
            server.write_bytes(b"selected own server")
            caller, proxy = root / "caller.exe", root / "proxy.dll"
            caller.write_bytes(b"caller")
            proxy.write_bytes(b"proxy")
            pair = root / "builtins"
            for architecture, filename in (
                    ("x86_64-windows", "wvb_autoconfig.dll"),
                    ("x86_64-unix", "wvb_autoconfig.so")):
                (pair / architecture).mkdir(parents=True)
                (pair / architecture / filename).write_bytes(b"real built artifact")
            hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (wine, server)]
            runtime = root / "new-runtime"
            process = Mock()
            process.poll.return_value = None
            result = {"observed_u32": 3276, "route": "generated-proxy"}
            with patch("setup.run_generated_call.subprocess.Popen", return_value=process) as launch, \
                    patch("setup.run_generated_call.subprocess.run",
                          return_value=subprocess.CompletedProcess([], 0)) as run, \
                    patch("setup.run_generated_call.run_proxy_call", return_value=result) as call:
                self.assertEqual(run_pid_demo(wine, *hashes, caller, proxy, pair,
                                              root / "call.json", runtime, 3276), result)
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
                self.assertEqual((runtime / "proxy.dll").read_bytes(), proxy.read_bytes())
                self.assertEqual(json.loads((runtime / "result.json").read_text()), result)
                launch.assert_called_once()
                self.assertEqual(launch.call_args.args[0],
                                 [str(server), "--foreground", "--persistent=2"])
                call.assert_called_once()
                process.wait.assert_called_once_with(timeout=10)
                process.terminate.assert_not_called()
                process.kill.assert_not_called()
                self.assertEqual([args.args[0][-1] for args in run.call_args_list],
                                 ["--init", "--shutdown"])
                self.assertEqual(run.call_args_list[-1].args[0][2:],
                                 ["--end-session", "--force", "--kill", "--shutdown"])
                environment = call.call_args.args[8]
                self.assertEqual(environment["WINEPREFIX"], str(runtime / "bottle"))
                self.assertNotIn("WHINY_WINE_BOOTSTRAP", environment)
                self.assertNotIn("CX_ROOT", environment)
                with self.assertRaises(FileExistsError):
                    run_pid_demo(wine, *hashes, caller, proxy, pair,
                                 root / "call.json", runtime, 3276)
                launch.assert_called_once()

            process.reset_mock()
            process.poll.return_value = None
            with patch("setup.run_generated_call.subprocess.Popen", return_value=process), \
                    patch("setup.run_generated_call.subprocess.run",
                          return_value=subprocess.CompletedProcess([], 0)), \
                    patch("setup.run_generated_call.run_proxy_call",
                          side_effect=RuntimeError("guest completion unknown")) as call:
                with self.assertRaisesRegex(RuntimeError, "guest completion unknown"):
                    run_pid_demo(wine, *hashes, caller, proxy, pair,
                                 root / "call.json", root / "failed-runtime", 3276)
                call.assert_called_once()
                process.wait.assert_called_once_with(timeout=10)
                process.terminate.assert_not_called()

            process.reset_mock()
            process.wait.side_effect = [subprocess.TimeoutExpired("wineserver", 10), 0]
            with patch("setup.run_generated_call.subprocess.Popen", return_value=process), \
                    patch("setup.run_generated_call.subprocess.run",
                          return_value=subprocess.CompletedProcess([], 0)), \
                    patch("setup.run_generated_call.run_proxy_call", return_value=result) as call:
                with self.assertRaisesRegex(RuntimeError, "prefix quiescence unknown"):
                    run_pid_demo(wine, *hashes, caller, proxy, pair,
                                 root / "call.json", root / "undrained-runtime", 3276)
                call.assert_called_once()
                process.terminate.assert_called_once()
                process.kill.assert_not_called()
                self.assertEqual([entry.kwargs["timeout"]
                                  for entry in process.wait.call_args_list], [10, 5])


if __name__ == "__main__":
    unittest.main()
