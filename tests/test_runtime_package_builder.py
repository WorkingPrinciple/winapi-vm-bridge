import io
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from setup.build_runtime_package import add_tree, build_macos_provisioner


class RuntimePackageBuilderTests(unittest.TestCase):
    def test_macos_provisioner_is_built_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "wvb-provision"
            destination.touch()
            with patch("setup.build_runtime_package.subprocess.run") as run:
                build_macos_provisioner(destination)
            command = run.call_args.args[0]
            self.assertEqual(command[0], "clang")
            self.assertIn("native/macos-keychain/src/wvb_provision.c", command)
            self.assertIn("native/macos-keychain/src/wvb_keychain.c", command)
            self.assertEqual(command[-2:], ["-o", str(destination)])
            self.assertEqual(run.call_args.kwargs, {"check": True})
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_tar_metadata_is_normalized_and_sorted(self):
        with tempfile.TemporaryDirectory() as source_directory:
            source = Path(source_directory)
            (source / "b").write_bytes(b"b")
            (source / "a").write_bytes(b"a")
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
                add_tree(archive, source, "package")
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], ["package/a", "package/b"])
                self.assertTrue(all(member.mtime == 0 for member in members))
                self.assertTrue(all(member.uid == 0 and member.gid == 0 for member in members))


if __name__ == "__main__":
    unittest.main()
