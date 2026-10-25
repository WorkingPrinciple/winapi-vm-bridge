"""Source-only rollback tests: temporary fixture files, no Wine subprocesses."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "loader_probe", Path(__file__).resolve().parents[1] / "run-loader-probe.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class PartialCreationCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wvb-a08-source-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root = base / "owned"
        self.evidence = base / "evidence"
        self.prefix = self.root / "bottle"
        sources = base / "sources"
        sources.mkdir()
        self.inputs = {}
        for name in ("loader_probe.exe", "wvb_autoconfig.dll", "wvb_autoconfig.so", "server"):
            directory = sources / (
                "x86_64-windows" if name.endswith(".dll") else "x86_64-unix"
            )
            directory.mkdir(exist_ok=True)
            source = directory / name
            source.write_bytes(name.encode("ascii"))
            self.inputs[source] = hashlib.sha256(source.read_bytes()).hexdigest()
        self.mkdir = Path.mkdir
        self.identity = probe.identity
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.multiple(
            probe, ROOT=self.root, EVIDENCE=self.evidence, PREFIX=self.prefix,
            INPUTS=self.inputs, SERVER=next(path for path in self.inputs if path.name == "server"),
        ))
        self.popen = self.patches.enter_context(mock.patch.object(
            probe.subprocess, "Popen", side_effect=AssertionError("Wine launch forbidden")
        ))
        self.run = self.patches.enter_context(mock.patch.object(
            probe.subprocess, "run", side_effect=AssertionError("subprocess execution forbidden")
        ))

    def execute_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.execute(), 1)
        self.popen.assert_not_called()
        self.run.assert_not_called()
        return json.loads((self.evidence / "report.json").read_text(encoding="utf-8"))

    def assert_restored(self, report):
        self.assertNotIn("cleanupError", report)
        self.assertFalse(self.root.exists())
        self.assertTrue(self.evidence.is_dir())
        self.assertNotIn("loaderOnlyEvidence", report)

    def test_copy_failure_restores_owned_root_without_starting_wine(self):
        with mock.patch.object(probe.shutil, "copyfile", side_effect=OSError("injected copy failure")):
            report = self.execute_failure()
        self.assertIn("injected copy failure", report["error"])
        self.assert_restored(report)

    def test_staged_hash_failure_restores_owned_root_without_starting_wine(self):
        def corrupt_copy(source, destination):
            destination.write_bytes(b"corrupt")

        with mock.patch.object(probe.shutil, "copyfile", side_effect=corrupt_copy):
            report = self.execute_failure()
        self.assertIn("staged hash mismatch", report["error"])
        self.assert_restored(report)

    def test_first_child_creation_failure_restores_owned_root(self):
        def fail_prefix(path, *args, **kwargs):
            if path == self.prefix:
                raise OSError("injected first child creation failure")
            return self.mkdir(path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", new=fail_prefix):
            report = self.execute_failure()
        self.assertIn("injected first child creation failure", report["error"])
        self.assert_restored(report)

    def test_intermediate_creation_failure_restores_partial_tree(self):
        def fail_intermediate(path, *args, **kwargs):
            if path == self.root / "pair/lib":
                raise OSError("injected intermediate creation failure")
            return self.mkdir(path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", new=fail_intermediate):
            report = self.execute_failure()
        self.assertIn("injected intermediate creation failure", report["error"])
        self.assert_restored(report)

    def test_root_creation_failure_preserves_evidence_without_cleanup_error(self):
        def fail_root(path, *args, **kwargs):
            if path == self.root:
                raise OSError("injected root creation failure")
            return self.mkdir(path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", new=fail_root):
            report = self.execute_failure()
        self.assertIn("injected root creation failure", report["error"])
        self.assert_restored(report)

    def test_unknown_created_directory_identity_stops_cleanup(self):
        def unknown_identity(path):
            if path == self.prefix:
                raise OSError("injected unavailable prefix identity")
            return self.identity(path)

        with mock.patch.object(probe, "identity", side_effect=unknown_identity):
            report = self.execute_failure()
        self.assertIn("injected unavailable prefix identity", report["error"])
        self.assertIn("cleanupError", report)
        self.assertTrue(self.root.is_dir())
        self.assertTrue(self.prefix.is_dir())

    def test_creation_collision_with_unknown_directory_stops_cleanup(self):
        def collide(path, *args, **kwargs):
            if path == self.prefix:
                self.mkdir(path)
                (path / "sentinel").write_bytes(b"do not delete")
                raise FileExistsError("injected concurrent creation")
            return self.mkdir(path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", new=collide):
            report = self.execute_failure()
        self.assertIn("injected concurrent creation", report["error"])
        self.assertIn("cleanupError", report)
        self.assertEqual((self.prefix / "sentinel").read_bytes(), b"do not delete")

    def test_replaced_created_directory_stops_cleanup(self):
        displaced = self.root / "displaced-home"

        def replace_home(source, destination):
            (self.root / "home").rename(displaced)
            (self.root / "home").mkdir()
            (self.root / "home/sentinel").write_bytes(b"do not delete")
            raise OSError("injected replacement during staging")

        with mock.patch.object(probe.shutil, "copyfile", side_effect=replace_home):
            report = self.execute_failure()
        self.assertIn("injected replacement during staging", report["error"])
        self.assertIn("cleanupError", report)
        self.assertTrue(displaced.is_dir())
        self.assertEqual((self.root / "home/sentinel").read_bytes(), b"do not delete")


if __name__ == "__main__":
    unittest.main()
