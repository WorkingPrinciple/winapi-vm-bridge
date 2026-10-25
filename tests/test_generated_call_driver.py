import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from setup.run_generated_call import (
    compare_com_oracle, main, read_com_oracle, run_call, run_com_demo, run_com_proxy, run_pid_demo,
    run_proxy_call,
)


class GeneratedCallDriverTests(unittest.TestCase):
    def com_inputs(self, root):
        (root / "system.reg").write_text("owned prefix")
        contract = root / "contract.json"
        contract.write_text(json.dumps({"target": {"relative_path": "com_scalar.exe"}, "object_slice": {
            "abi": "com-u32-v1",
            "activation": {"kind": "com-local-server", "clsid": "BA9A4DA2-79FE-4B31-8DB4-201AF0266C11"},
            "interface_iid": "BA9A4DA2-79FE-4B31-8DB4-201AF0266C12",
            "method_slot": 3,
        }}))
        key = root / "client.key"
        key.write_bytes(b"\x07" * 32)
        key.chmod(0o600)
        proxy, wine, config = root / "proxy.dll", root / "wine", root / "call.json"
        proxy.write_bytes(b"generated COM facade")
        wine.write_bytes(b"Calimocho engine")
        value = {
            "contract_path": str(contract),
            "contract_sha256": list(hashlib.sha256(contract.read_bytes()).digest()),
            "private_key_path": str(key), "address": "192.168.64.4:47963",
            "broker_public_key": [1] * 32, "actor_id": [2] * 16,
            "client_instance": [3] * 16, "build_fingerprint": [4] * 32,
            "connect_timeout_ms": 5000, "call_timeout_ms": 10000,
        }
        config.write_text(json.dumps(value))
        rows = [
            {"event": "result", "activation_hresult": 0, "hresult": 0,
             "output": 42, "caller_pid": 32},
            {"event": "native-error", "hresult": -2147024809, "output": 0},
            {"event": "release", "references": 0, "can_unload_hresult": 0, "recording": False},
            {"event": "control-negatives", "wrong_epoch": True, "wrong_generation": True,
             "wrong_type": True, "lease_survived": True, "closed": True, "stale": True},
        ]
        arguments = [wine, root / "caller.exe", proxy, config, root / "response.jsonl",
                     root / "trace.jsonl", hashlib.sha256(wine.read_bytes()).hexdigest(),
                     {"WINEPREFIX": str(root), "WINEDLLPATH": str(root / "pair")},
                     root / "caller.stderr"]
        return arguments, rows, value

    def test_com_caller_is_one_shot_and_preserves_evidence_without_inventing_recording(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            arguments, rows, _ = self.com_inputs(root)
            output = "\n".join(json.dumps(row) for row in rows) + "\n"
            def invoke(command, **kwargs):
                self.assertEqual(len(command), 12)
                self.assertEqual(command[0:2], [str(root / "wine"), str(root / "caller.exe")])
                self.assertIn("Z:" + str(root / "client.key").replace("/", "\\"), command)
                self.assertNotIn("07" * 32, command)
                self.assertEqual(kwargs["timeout"], 60)
                return subprocess.CompletedProcess(command, 0, output, "recorder unavailable\n")
            with patch("setup.run_generated_call.subprocess.run", side_effect=invoke) as run:
                result = run_com_proxy(*arguments)
                self.assertTrue(result["supporting_only"])
                self.assertFalse(result["native_oracle_compared"])
                self.assertFalse(result["generated_recording"])
                self.assertEqual(arguments[4].read_text(), output)
                self.assertEqual(arguments[4].stat().st_mode & 0o777, 0o600)
                self.assertFalse(arguments[5].exists())
                with self.assertRaisesRegex(ValueError, "never reuse"):
                    run_com_proxy(*arguments)
                run.assert_called_once()

    def test_com_caller_rejects_wrong_writeback_release_and_malformed_output(self):
        for field, value, index in (
                ("output", 43, 0), ("activation_hresult", 1, 0),
                ("hresult", 0, 1), ("output", 0xa5a5a5a5, 1),
                ("references", 1, 2), ("recording", "true", 2),
                ("hresult", False, 0), ("stale", False, 3)):
            with self.subTest(field=field, value=value, index=index), \
                    tempfile.TemporaryDirectory() as directory:
                arguments, rows, _ = self.com_inputs(Path(directory).resolve())
                rows[index][field] = value
                output = "\n".join(json.dumps(row) for row in rows)
                with patch("setup.run_generated_call.subprocess.run",
                           return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
                    with self.assertRaisesRegex(ValueError, "did not prove"):
                        run_com_proxy(*arguments)
                    self.assertEqual(arguments[4].read_text(), output)
                    run.assert_called_once()

    def test_com_timeout_retains_partial_observation_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments, _, _ = self.com_inputs(Path(directory).resolve())
            with patch("setup.run_generated_call.subprocess.run",
                       side_effect=subprocess.TimeoutExpired("caller", 60,
                           output=b"partial\n", stderr=b"observed stderr\n")) as run:
                with self.assertRaisesRegex(RuntimeError, "guest completion unknown"):
                    run_com_proxy(*arguments)
                self.assertEqual(arguments[4].read_bytes(), b"partial\n")
                self.assertIn("observed stderr", arguments[-1].read_text())
                run.assert_called_once()

    def test_com_wrong_contract_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments, _, value = self.com_inputs(Path(directory).resolve())
            contract = Path(value["contract_path"])
            contract.write_text('{"object_slice":{"abi":"winrt"}}')
            value["contract_sha256"] = list(hashlib.sha256(contract.read_bytes()).digest())
            arguments[3].write_text(json.dumps(value))
            with patch("setup.run_generated_call.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "exact class/interface"):
                    run_com_proxy(*arguments)
                run.assert_not_called()
                self.assertFalse(arguments[4].exists())

    def test_com_oracle_is_hash_pinned_and_compared_cell_by_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            arguments, rows, _ = self.com_inputs(root)
            native = root / "native.stdout"
            native.write_text(json.dumps({
                "event": "oracle", "input": 41, "hresult": 0, "output": 42, "caller_pid": 6084,
            }) + "\n" + json.dumps({
                "event": "oracle-error", "hresult": -2147024809, "output": 0,
            }) + "\n")
            pin = hashlib.sha256(native.read_bytes()).hexdigest()
            baseline = read_com_oracle(native, pin)
            arguments[4].write_text("\n".join(json.dumps(row) for row in rows))
            cells = compare_com_oracle(baseline, arguments[4])
            self.assertEqual(len(cells), 4)
            self.assertEqual(cells["native-error.output"], {"native": 0, "generated": 0, "equal": True})
            rows[1]["output"] = 0xa5a5a5a5
            arguments[4].write_text("\n".join(json.dumps(row) for row in rows))
            with self.assertRaisesRegex(ValueError, "native-error.output"):
                compare_com_oracle(baseline, arguments[4])
            with patch("setup.run_generated_call.subprocess.Popen") as launch:
                with self.assertRaisesRegex(ValueError, "oracle hash mismatch"):
                    run_com_demo(root / "wine", "0" * 64, "0" * 64, root / "caller.exe",
                                 root / "proxy.dll", root / "pair", arguments[3],
                                 root / "must-not-create", native, "0" * 64)
                launch.assert_not_called()
                self.assertFalse((root / "must-not-create").exists())

    def test_com_oracle_rejects_malformed_native_evidence_before_runtime(self):
        baseline = [
            {"event": "oracle", "input": 41, "hresult": 0, "output": 42, "caller_pid": 6084},
            {"event": "oracle-error", "hresult": -2147024809, "output": 0},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, field, value in (
                    (0, "caller_pid", 0), (0, "input", 42), (0, "hresult", False),
                    (1, "output", 0xa5a5a5a5), (1, "output", False),
                    (1, "hresult", 0), (1, "event", "transport-error")):
                with self.subTest(field=field, value=value):
                    rows = [dict(row) for row in baseline]
                    rows[index][field] = value
                    native = root / "native.stdout"
                    native.write_text("\n".join(json.dumps(row) for row in rows))
                    pin = hashlib.sha256(native.read_bytes()).hexdigest()
                    with patch("setup.run_generated_call.run_isolated_demo") as launch:
                        with self.assertRaisesRegex(ValueError, "observed OOP fixture baseline"):
                            run_com_demo(root / "wine", "0" * 64, "0" * 64, root / "caller",
                                         root / "proxy", root / "pair", root / "config",
                                         root / "runtime", native, pin)
                        launch.assert_not_called()
            generated = root / "generated.stdout"
            for rows in ([], [baseline[0]], [[], {}], [{}, {}]):
                generated.write_text("\n".join(json.dumps(row) for row in rows))
                with self.assertRaisesRegex(ValueError, "comparison rows are malformed"):
                    compare_com_oracle(baseline, generated)

    def test_com_oracle_cli_options_are_paired_and_com_only(self):
        for options in (
                ["--demo-com", "--oracle-stdout", "native"],
                ["--demo-com", "--oracle-sha256", "0" * 64],
                ["--demo-pid", "--oracle-stdout", "native", "--oracle-sha256", "0" * 64],
                ["--oracle-stdout", "native", "--oracle-sha256", "0" * 64]):
            with self.subTest(options=options), \
                    patch("sys.argv", ["driver", "--proxy-caller", "caller", "--config", "config", *options]), \
                    patch("sys.stderr", new_callable=io.StringIO) as error, \
                    patch("setup.run_generated_call.run_com_demo") as launch:
                with self.assertRaises(SystemExit) as failure:
                    main()
                self.assertEqual(failure.exception.code, 2)
                self.assertIn("paired option for --demo-com only", error.getvalue())
                launch.assert_not_called()

    def test_com_demo_rejects_missing_or_wrong_validator_pin_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validator = root / "whiny"
            validator.write_bytes(b"validator")
            for tool, pin in ((None, None), (validator, "0" * 64)):
                with self.subTest(tool=tool), \
                        patch("setup.run_generated_call.run_isolated_demo") as launch:
                    with self.assertRaisesRegex(ValueError, "COM trace"):
                        run_com_demo(root / "wine", "0" * 64, "0" * 64, root / "caller",
                                     root / "proxy", root / "pair", root / "config", root / "runtime",
                                     whiny=tool, whiny_sha256=pin)
                    launch.assert_not_called()

    def test_com_recording_must_be_complete_paired_and_bound(self):
        for mode in ("good", "unmatched", "wrong-hash", "empty", "release-failed",
                     "validator-rejects", "validator-incomplete", "validator-timeout", "validator-json"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                arguments, rows, value = self.com_inputs(Path(directory).resolve())
                rows[2]["recording"] = True
                validator = Path(directory) / "whiny"
                validator.write_bytes(b"pinned Whiny validator")
                validator_hash = hashlib.sha256(validator.read_bytes()).hexdigest()
                def invoke(command, **kwargs):
                    if command[0] == str(validator):
                        self.assertEqual(command[1:], ["trace", str(arguments[5])])
                        if mode == "validator-timeout":
                            raise subprocess.TimeoutExpired(command, 30, output=b"partial")
                        if mode == "validator-json":
                            return subprocess.CompletedProcess(command, 0, "not JSON", "")
                        summary = {
                            "complete": mode != "validator-incomplete", "calls": 5, "events": 12,
                            "dropped_events": 0, "route": "remote",
                            "contract_sha256": bytes(value["contract_sha256"]).hex(),
                            "proxy_artifact_sha256": hashlib.sha256(arguments[2].read_bytes()).hexdigest(),
                        }
                        return subprocess.CompletedProcess(command, 2 if mode == "validator-rejects" else 0,
                            json.dumps(summary), "INVALID_CALL_TRACE" if mode == "validator-rejects" else "")
                    records = []
                    method = "com_scalar.exe!BA9A4DA2-79FE-4B31-8DB4-201AF0266C12#3"
                    calls = [
                        ("com_scalar.exe!BA9A4DA2-79FE-4B31-8DB4-201AF0266C11::activate", "ok"),
                        (method, "invalid_input"), (method, "ok"), (method, "call_failed"),
                        ("com_scalar.exe!BA9A4DA2-79FE-4B31-8DB4-201AF0266C12::release",
                         "call_failed" if mode == "release-failed" else "ok"),
                    ]
                    events = [("run_start", "", "", "")]
                    if mode != "empty":
                        for number, (target, status) in enumerate(calls):
                            events += [("entry", str(number), target, ""),
                                       ("return", str(number), target, status)]
                    events += [("run_end", "", "", "")]
                    for index, (kind, call_id, target, status) in enumerate(events):
                        records.append({
                            "kind": kind, "sequence": index, "route": "remote",
                            "proxy_artifact_sha256": command[-2] if mode != "wrong-hash" else "0" * 64,
                            "contract_sha256": bytes(value["contract_sha256"]).hex(),
                            "process_id": 32, "complete": True,
                            "call_id": "99" if mode == "unmatched" and kind == "return" else call_id,
                            "target": target, "status": status,
                        })
                    arguments[5].write_text("\n".join(json.dumps(row) for row in records))
                    return subprocess.CompletedProcess(command, 0,
                        "\n".join(json.dumps(row) for row in rows), "")
                with patch("setup.run_generated_call.subprocess.run", side_effect=invoke) as run:
                    if mode == "good":
                        result = run_com_proxy(*arguments, whiny=validator, whiny_sha256=validator_hash)
                        self.assertTrue(result["generated_recording"])
                        self.assertTrue(result["trace_validated"])
                    else:
                        with self.assertRaisesRegex(
                                RuntimeError if mode == "validator-timeout" else ValueError, "COM trace"):
                            run_com_proxy(*arguments, whiny=validator, whiny_sha256=validator_hash)
                    self.assertEqual(run.call_count, 2 if mode in (
                        "good", "validator-rejects", "validator-incomplete",
                        "validator-timeout", "validator-json") else 1)

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

    def test_com_demo_uses_the_same_private_lifecycle_and_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "bin").mkdir()
            wine, server = root / "bin/wine", root / "bin/wineserver"
            wine.write_bytes(b"Calimocho")
            server.write_bytes(b"Calimocho server")
            caller, proxy = root / "caller.exe", root / "proxy.dll"
            caller.write_bytes(b"owned caller")
            proxy.write_bytes(b"generated facade")
            for architecture, name in (("x86_64-windows", "wvb_autoconfig.dll"),
                                       ("x86_64-unix", "wvb_autoconfig.so")):
                folder = root / "pair" / architecture
                folder.mkdir(parents=True)
                (folder / name).write_bytes(b"matched builtin")
            hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (wine, server)]
            validator = root / "whiny"
            validator.write_bytes(b"pinned validator")
            validator_hash = hashlib.sha256(validator.read_bytes()).hexdigest()
            process = Mock()
            process.poll.return_value = None
            for failed in (False, True):
                with self.subTest(failed=failed), \
                        patch("setup.run_generated_call.subprocess.Popen", return_value=process), \
                        patch("setup.run_generated_call.subprocess.run",
                              return_value=subprocess.CompletedProcess([], 0)), \
                        patch("setup.run_generated_call.run_com_proxy") as call:
                    runtime = root / f"runtime-{failed}"
                    if failed:
                        call.side_effect = RuntimeError("guest completion unknown")
                        with self.assertRaisesRegex(RuntimeError, "guest completion unknown"):
                            run_com_demo(wine, *hashes, caller, proxy, root / "pair",
                                         root / "config.json", runtime,
                                         whiny=validator, whiny_sha256=validator_hash)
                    else:
                        call.return_value = {"supporting_only": True, "trace_validated": True}
                        self.assertEqual(run_com_demo(wine, *hashes, caller, proxy, root / "pair",
                                          root / "config.json", runtime,
                                          whiny=validator, whiny_sha256=validator_hash), call.return_value)
                    call.assert_called_once()
                    self.assertEqual(call.call_args.args[7]["WINEPREFIX"], str(runtime / "bottle"))
                    self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
                    process.wait.assert_called_once_with(timeout=10)
                    process.terminate.assert_not_called()
                    process.reset_mock()


if __name__ == "__main__":
    unittest.main()
