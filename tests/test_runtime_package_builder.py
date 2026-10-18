import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from setup.build_runtime_package import add_tree


class RuntimePackageBuilderTests(unittest.TestCase):
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
